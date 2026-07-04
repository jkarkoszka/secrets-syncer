package planner

import (
	"context"
	"fmt"
	"maps"
	"reflect"

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

		if needsUpdate(d, *remote, remoteValue.Value) {
			plan.addAction(Action{Type: ActionUpdate, Key: d.Key, Desired: d})
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

func needsUpdate(desired provider.DesiredSecret, remote provider.RemoteSecret, remoteValue string) bool {
	if desired.Value != remoteValue {
		return true
	}
	if desired.Description != remote.Description {
		return true
	}
	if desired.EncryptionKey != "" && desired.EncryptionKey != remote.EncryptionKey {
		return true
	}
	return !tagsEqual(desired.Tags, remote.Tags)
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
