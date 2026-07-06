package planner

import (
	"context"
	"fmt"
	"maps"
	"reflect"
	"sort"

	"github.com/jkarkoszka/secrets-syncer/internal/provider"
)

// ActionType is the kind of planned change.
type ActionType string

const (
	ActionCreate   ActionType = "create"
	ActionUpdate   ActionType = "update"
	ActionDelete   ActionType = "delete"
	ActionNoChange ActionType = "no-change"
)

// Action is a single planned change.
type Action struct {
	Type    ActionType
	Key     string
	Desired provider.DesiredSecret
	Changes *ChangeSet
}

// Conflict is an unmanaged secret that blocks changes.
type Conflict struct {
	Key    string
	Reason string
}

// Stats summarizes plan counts.
type Stats struct {
	Add     int
	Change  int
	Destroy int
}

// Plan is the result of comparing desired and remote state.
type Plan struct {
	Actions   []Action
	Conflicts []Conflict
	Stats     Stats
}

// ChangeSet describes the planned updates for a secret.
type ChangeSet struct {
	Value            bool
	Description      bool
	DescriptionOld   string
	DescriptionNew   string
	EncryptionKey    bool
	EncryptionKeyOld string
	EncryptionKeyNew string
	Tags             []TagChange
}

// HasChanges reports whether the change set includes any updates.
func (c *ChangeSet) HasChanges() bool {
	if c == nil {
		return false
	}
	return c.Value || c.Description || c.EncryptionKey || len(c.Tags) > 0
}

// TagChangeType describes the tag mutation kind.
type TagChangeType string

const (
	TagAdded   TagChangeType = "added"
	TagUpdated TagChangeType = "updated"
	TagRemoved TagChangeType = "removed"
)

// TagChange captures a single tag change.
type TagChange struct {
	Type     TagChangeType
	Key      string
	OldValue string
	NewValue string
}

// HasChanges reports whether the plan includes create, update, or delete actions.
func (p *Plan) HasChanges() bool {
	return p.Stats.Add > 0 || p.Stats.Change > 0 || p.Stats.Destroy > 0
}

// HasConflicts reports whether unmanaged conflicts were detected.
func (p *Plan) HasConflicts() bool {
	return len(p.Conflicts) > 0
}

// Options configure plan generation.
type Options struct {
	Prune bool
}

// Generate builds a plan from desired secrets and remote provider state.
func Generate(ctx context.Context, prov provider.SecretProvider, desired []provider.DesiredSecret, opts Options) (*Plan, error) {
	plan := &Plan{}

	desiredKeys := make(map[string]provider.DesiredSecret, len(desired))
	for _, d := range desired {
		desiredKeys[d.Key] = d
	}

	for _, d := range desired {
		remote, err := prov.DescribeSecret(ctx, d.Key)
		if err != nil {
			return nil, fmt.Errorf("describe secret %s: %w", d.Key, err)
		}

		if remote == nil {
			plan.addAction(Action{Type: ActionCreate, Key: d.Key, Desired: d})
			continue
		}

		if !remote.Managed {
			plan.Conflicts = append(plan.Conflicts, Conflict{
				Key:    d.Key,
				Reason: fmt.Sprintf("missing tag %s=%s", provider.ManagedTagKey, provider.ManagedTagValue),
			})
			continue
		}

		remoteValue, err := prov.GetSecretValue(ctx, d.Key)
		if err != nil {
			return nil, fmt.Errorf("get secret value %s: %w", d.Key, err)
		}

		changeSet := diffSecret(d, *remote, remoteValue.Value)
		if changeSet.HasChanges() {
			plan.addAction(Action{Type: ActionUpdate, Key: d.Key, Desired: d, Changes: changeSet})
		} else {
			plan.addAction(Action{Type: ActionNoChange, Key: d.Key, Desired: d})
		}
	}

	if opts.Prune {
		managed, err := prov.ListManagedSecrets(ctx)
		if err != nil {
			return nil, fmt.Errorf("list managed secrets: %w", err)
		}
		for _, remote := range managed {
			if _, ok := desiredKeys[remote.Key]; !ok {
				plan.addAction(Action{Type: ActionDelete, Key: remote.Key})
			}
		}
	}

	return plan, nil
}

func (p *Plan) addAction(action Action) {
	switch action.Type {
	case ActionCreate:
		p.Stats.Add++
	case ActionUpdate:
		p.Stats.Change++
	case ActionDelete:
		p.Stats.Destroy++
	case ActionNoChange:
		// not counted in summary
	}
	if action.Type != ActionNoChange {
		p.Actions = append(p.Actions, action)
	}
}

func diffSecret(desired provider.DesiredSecret, remote provider.RemoteSecret, remoteValue string) *ChangeSet {
	changeSet := &ChangeSet{}
	if desired.Value != remoteValue {
		changeSet.Value = true
	}
	if desired.Description != remote.Description {
		changeSet.Description = true
		changeSet.DescriptionOld = remote.Description
		changeSet.DescriptionNew = desired.Description
	}
	if desired.EncryptionKey != "" && desired.EncryptionKey != remote.EncryptionKey {
		changeSet.EncryptionKey = true
		changeSet.EncryptionKeyOld = remote.EncryptionKey
		changeSet.EncryptionKeyNew = desired.EncryptionKey
	}
	changeSet.Tags = diffTags(desired.Tags, remote.Tags)
	return changeSet
}

func tagsEqual(desired map[string]string, remote map[string]string) bool {
	filteredRemote := make(map[string]string, len(remote))
	for k, v := range remote {
		if k == provider.ManagedTagKey {
			continue
		}
		filteredRemote[k] = v
	}

	if len(desired) == 0 && len(filteredRemote) == 0 {
		return true
	}
	return reflect.DeepEqual(desired, filteredRemote)
}

func diffTags(desired map[string]string, remote map[string]string) []TagChange {
	filteredRemote := make(map[string]string, len(remote))
	for k, v := range remote {
		if k == provider.ManagedTagKey {
			continue
		}
		filteredRemote[k] = v
	}

	changes := make([]TagChange, 0)
	seen := make(map[string]struct{}, len(desired))
	for k, desiredValue := range desired {
		seen[k] = struct{}{}
		if remoteValue, ok := filteredRemote[k]; !ok {
			changes = append(changes, TagChange{
				Type:     TagAdded,
				Key:      k,
				NewValue: desiredValue,
			})
		} else if remoteValue != desiredValue {
			changes = append(changes, TagChange{
				Type:     TagUpdated,
				Key:      k,
				OldValue: remoteValue,
				NewValue: desiredValue,
			})
		}
	}

	for k, remoteValue := range filteredRemote {
		if _, ok := seen[k]; ok {
			continue
		}
		changes = append(changes, TagChange{
			Type:     TagRemoved,
			Key:      k,
			OldValue: remoteValue,
		})
	}

	sort.Slice(changes, func(i, j int) bool {
		return changes[i].Key < changes[j].Key
	})

	return changes
}

// Apply executes all mutating actions in the plan.
func Apply(ctx context.Context, prov provider.SecretProvider, plan *Plan) (Stats, error) {
	stats := Stats{}
	for _, action := range plan.Actions {
		switch action.Type {
		case ActionCreate:
			if err := prov.CreateSecret(ctx, action.Desired); err != nil {
				return stats, fmt.Errorf("create secret %s: %w", action.Key, err)
			}
			stats.Add++
		case ActionUpdate:
			if err := prov.UpdateSecret(ctx, action.Desired); err != nil {
				return stats, fmt.Errorf("update secret %s: %w", action.Key, err)
			}
			stats.Change++
		case ActionDelete:
			if err := prov.DeleteSecret(ctx, action.Key); err != nil {
				return stats, fmt.Errorf("delete secret %s: %w", action.Key, err)
			}
			stats.Destroy++
		}
	}
	return stats, nil
}

// MergeTags returns desired tags with the management tag applied.
func MergeTags(tags map[string]string) map[string]string {
	out := make(map[string]string, len(tags)+1)
	maps.Copy(out, tags)
	out[provider.ManagedTagKey] = provider.ManagedTagValue
	return out
}
