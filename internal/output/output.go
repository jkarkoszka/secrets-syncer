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
func (f *Formatter) WritePlan(plan *planner.Plan) error {
	if plan.HasChanges() {
		fmt.Fprintln(f.w, "Secrets Syncer will perform the following actions:")
		fmt.Fprintln(f.w)
		for _, action := range plan.Actions {
			switch action.Type {
			case planner.ActionCreate:
				fmt.Fprintf(f.w, "  %s create %s\n", createColor("+"), action.Key)
			case planner.ActionUpdate:
				fmt.Fprintf(f.w, "  %s update %s\n", updateColor("~"), action.Key)
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
