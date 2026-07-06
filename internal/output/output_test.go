package output_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jkarkoszka/secrets-syncer/internal/output"
	"github.com/jkarkoszka/secrets-syncer/internal/planner"
)

func TestWritePlanSummary(t *testing.T) {
	t.Parallel()
	output.SetNoColor(true)

	var buf bytes.Buffer
	formatter := output.NewFormatterWithWriter(&buf)
	plan := &planner.Plan{
		Actions: []planner.Action{
			{Type: planner.ActionCreate, Key: "/dev1/networking/bgp_auth_key"},
			{Type: planner.ActionUpdate, Key: "/dev1/github/webhook_secret"},
		},
		Stats: planner.Stats{Add: 1, Change: 1},
	}

	if err := formatter.WritePlan(plan, output.Scope{}); err != nil {
		t.Fatal(err)
	}

	got := buf.String()
	if !strings.Contains(got, "+ create /dev1/networking/bgp_auth_key") {
		t.Fatalf("create action missing: %q", got)
	}
	if !strings.Contains(got, "~ update /dev1/github/webhook_secret") {
		t.Fatalf("update action missing: %q", got)
	}
	if !strings.Contains(got, "Plan: 1 to add, 1 to change, 0 to destroy.") {
		t.Fatalf("summary missing: %q", got)
	}
	if output.ContainsSecretValue(got, "example-secret-value", "another-secret-value") {
		t.Fatal("secret value leaked into plan output")
	}
}

func TestWritePlanNoChanges(t *testing.T) {
	t.Parallel()
	output.SetNoColor(true)

	var buf bytes.Buffer
	formatter := output.NewFormatterWithWriter(&buf)
	plan := &planner.Plan{}

	if err := formatter.WritePlan(plan, output.Scope{}); err != nil {
		t.Fatal(err)
	}

	got := buf.String()
	if !strings.Contains(got, "No changes. Your secrets match the desired configuration.") {
		t.Fatalf("no-change message missing: %q", got)
	}
}

func TestWriteConflict(t *testing.T) {
	t.Parallel()
	output.SetNoColor(true)

	var buf bytes.Buffer
	formatter := output.NewFormatterWithWriter(&buf)
	plan := &planner.Plan{
		Conflicts: []planner.Conflict{{
			Key:    "/dev1/github/webhook_secret",
			Reason: "missing tag secrets_syncer_managed=true",
		}},
	}

	if err := formatter.WritePlan(plan, output.Scope{}); err != nil {
		t.Fatal(err)
	}

	got := buf.String()
	if !strings.Contains(got, "Error: Secret exists but is not managed by secrets-syncer") {
		t.Fatalf("conflict header missing: %q", got)
	}
	if output.ContainsSecretValue(got, "another-secret-value") {
		t.Fatal("secret value leaked into conflict output")
	}
}

func TestWriteApplyComplete(t *testing.T) {
	t.Parallel()
	output.SetNoColor(true)

	var buf bytes.Buffer
	formatter := output.NewFormatterWithWriter(&buf)
	formatter.WriteApplyComplete(planner.Stats{Add: 1, Change: 1})

	got := buf.String()
	if !strings.Contains(got, "Apply complete! Resources: 1 added, 1 changed, 0 destroyed.") {
		t.Fatalf("apply summary missing: %q", got)
	}
}
