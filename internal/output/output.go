package output

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/jkarkoszka/secrets-syncer/internal/planner"
)

var (
	createColor = color.New(color.FgGreen).SprintFunc()
	updateColor = color.New(color.FgYellow).SprintFunc()
	deleteColor = color.New(color.FgRed).SprintFunc()
	errColor    = color.New(color.FgRed).SprintFunc()
	okColor     = color.New(color.FgGreen).SprintFunc()
)

// Formatter renders Terraform-style plan and apply output.
type Formatter struct {
	w io.Writer
}

var defaultWriter io.Writer = os.Stdout

// SetWriter overrides the default output writer (for tests).
func SetWriter(w io.Writer) {
	defaultWriter = w
}

// ResetWriter restores stdout as the default output writer.
func ResetWriter() {
	defaultWriter = os.Stdout
}

// NewFormatter creates a formatter writing to the default writer.
func NewFormatter() *Formatter {
	return &Formatter{w: defaultWriter}
}

// NewFormatterWithWriter creates a formatter with a custom writer.
func NewFormatterWithWriter(w io.Writer) *Formatter {
	return &Formatter{w: w}
}

// SetNoColor disables ANSI styling.
func SetNoColor(disable bool) {
	color.NoColor = disable
}

func init() {
	if os.Getenv("NO_COLOR") != "" {
		color.NoColor = true
	}
}

// WritePlan renders a plan summary.
func (f *Formatter) WritePlan(plan *planner.Plan, scope Scope) error {
	f.writeScope(scope)
	if plan.HasChanges() {
		fmt.Fprintln(f.w, "Secrets Syncer will perform the following actions:")
		fmt.Fprintln(f.w)
		for _, action := range plan.Actions {
			switch action.Type {
			case planner.ActionCreate:
				fmt.Fprintf(f.w, "  %s create %s\n", createColor("+"), action.Key)
			case planner.ActionUpdate:
				fmt.Fprintf(f.w, "  %s update %s\n", updateColor("~"), action.Key)
				f.writeUpdateDetails(action)
			case planner.ActionDelete:
				fmt.Fprintf(f.w, "  %s destroy %s\n", deleteColor("-"), action.Key)
			}
		}
		fmt.Fprintln(f.w)
	} else if len(plan.Conflicts) == 0 {
		fmt.Fprintln(f.w, "No changes. Your secrets match the desired configuration.")
		fmt.Fprintln(f.w)
	}

	for _, conflict := range plan.Conflicts {
		if err := f.writeConflict(conflict); err != nil {
			return err
		}
	}

	fmt.Fprintf(f.w, "Plan: %d to add, %d to change, %d to destroy.\n",
		plan.Stats.Add, plan.Stats.Change, plan.Stats.Destroy)
	return nil
}

func (f *Formatter) writeConflict(conflict planner.Conflict) error {
	fmt.Fprintln(f.w, errColor("Error: Secret exists but is not managed by secrets-syncer"))
	fmt.Fprintln(f.w)
	fmt.Fprintf(f.w, "  Secret: %s\n", conflict.Key)
	fmt.Fprintf(f.w, "  Reason: %s\n", conflict.Reason)
	fmt.Fprintln(f.w)
	fmt.Fprintln(f.w, "This secret will not be modified.")
	fmt.Fprintln(f.w)
	return nil
}

// Scope describes the runtime context for plan/apply.
type Scope struct {
	Provider     string
	Region       string
	AccountID    string
	AccountAlias string
	AccountNote  string
	Profile      string
	RoleARN      string
}

func (s Scope) hasInfo() bool {
	return s.Provider != "" || s.Region != "" || s.AccountID != "" || s.AccountAlias != "" || s.Profile != "" || s.RoleARN != ""
}

func (f *Formatter) writeScope(scope Scope) {
	if !scope.hasInfo() {
		return
	}

	fmt.Fprintln(f.w, "Scope:")
	if scope.Provider != "" {
		fmt.Fprintf(f.w, "  Provider: %s\n", scope.Provider)
	}
	if scope.Region != "" {
		fmt.Fprintf(f.w, "  Region: %s\n", scope.Region)
	}
	if scope.AccountID != "" {
		accountLine := scope.AccountID
		if scope.AccountAlias != "" {
			accountLine = fmt.Sprintf("%s (%s)", scope.AccountID, scope.AccountAlias)
		}
		if scope.AccountNote != "" {
			accountLine = fmt.Sprintf("%s (%s)", accountLine, scope.AccountNote)
		}
		fmt.Fprintf(f.w, "  Account: %s\n", accountLine)
	}
	if scope.Profile != "" {
		fmt.Fprintf(f.w, "  Profile: %s\n", scope.Profile)
	}
	if scope.RoleARN != "" {
		fmt.Fprintf(f.w, "  Role: %s\n", scope.RoleARN)
	}
	fmt.Fprintln(f.w)
}

func (f *Formatter) writeUpdateDetails(action planner.Action) {
	if action.Changes == nil || !action.Changes.HasChanges() {
		return
	}

	if action.Changes.Value {
		fmt.Fprintln(f.w, "    value: (sensitive)")
	}
	if action.Changes.Description {
		fmt.Fprintf(f.w, "    description: %s -> %s\n",
			formatOptional(action.Changes.DescriptionOld),
			formatOptional(action.Changes.DescriptionNew))
	}
	if action.Changes.EncryptionKey {
		fmt.Fprintf(f.w, "    encryption_key: %s -> %s\n",
			formatOptional(action.Changes.EncryptionKeyOld),
			formatOptional(action.Changes.EncryptionKeyNew))
	}
	for _, tagChange := range action.Changes.Tags {
		switch tagChange.Type {
		case planner.TagAdded:
			fmt.Fprintf(f.w, "    tag + %s=%s\n", tagChange.Key, tagChange.NewValue)
		case planner.TagUpdated:
			fmt.Fprintf(f.w, "    tag ~ %s: %s -> %s\n", tagChange.Key, tagChange.OldValue, tagChange.NewValue)
		case planner.TagRemoved:
			fmt.Fprintf(f.w, "    tag - %s\n", tagChange.Key)
		}
	}
}

func formatOptional(value string) string {
	if value == "" {
		return "<empty>"
	}
	return value
}

// WriteApplyComplete renders the apply summary line.
func (f *Formatter) WriteApplyComplete(stats planner.Stats) {
	fmt.Fprintf(f.w, "\n%s Resources: %d added, %d changed, %d destroyed.\n",
		okColor("Apply complete!"), stats.Add, stats.Change, stats.Destroy)
}

// WriteValidateSuccess prints validation success.
func (f *Formatter) WriteValidateSuccess() {
	fmt.Fprintln(f.w, okColor("Success! The configuration is valid."))
}

// ContainsSecretValue reports whether s contains any of the given secret values.
func ContainsSecretValue(s string, values ...string) bool {
	for _, v := range values {
		if v != "" && strings.Contains(s, v) {
			return true
		}
	}
	return false
}
