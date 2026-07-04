package planner_test

import (
	"context"
	"testing"

	"github.com/jkarkoszka/secrets-syncer/internal/planner"
	"github.com/jkarkoszka/secrets-syncer/internal/provider"
	"github.com/jkarkoszka/secrets-syncer/internal/testutil"
)

func TestPlanCreate(t *testing.T) {
	t.Parallel()

	mock := testutil.NewMockProvider()
	plan, err := planner.Generate(context.Background(), mock, []provider.DesiredSecret{
		{Key: "/new", Value: "example-secret-value"},
	}, planner.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Stats.Add != 1 {
		t.Fatalf("add = %d", plan.Stats.Add)
	}
}

func TestPlanUpdate(t *testing.T) {
	t.Parallel()

	mock := testutil.NewMockProvider()
	mock.Seed("/existing", "old-value", "desc", "", map[string]string{"env": "dev"}, true)

	plan, err := planner.Generate(context.Background(), mock, []provider.DesiredSecret{
		{Key: "/existing", Value: "new-value", Tags: map[string]string{"env": "dev"}},
	}, planner.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Stats.Change != 1 {
		t.Fatalf("change = %d", plan.Stats.Change)
	}
}

func TestPlanNoChange(t *testing.T) {
	t.Parallel()

	mock := testutil.NewMockProvider()
	mock.Seed("/same", "same-value", "", "", nil, true)

	plan, err := planner.Generate(context.Background(), mock, []provider.DesiredSecret{
		{Key: "/same", Value: "same-value"},
	}, planner.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if plan.HasChanges() {
		t.Fatal("expected no changes")
	}
}

func TestPlanConflict(t *testing.T) {
	t.Parallel()

	mock := testutil.NewMockProvider()
	mock.Seed("/unmanaged", "value", "", "", nil, false)

	plan, err := planner.Generate(context.Background(), mock, []provider.DesiredSecret{
		{Key: "/unmanaged", Value: "new"},
	}, planner.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.HasConflicts() {
		t.Fatal("expected conflict")
	}
	if plan.Stats.Add+plan.Stats.Change > 0 {
		t.Fatal("should not plan changes for conflict")
	}
}

func TestPlanDeleteOnlyWithPrune(t *testing.T) {
	t.Parallel()

	mock := testutil.NewMockProvider()
	mock.Seed("/orphan", "value", "", "", nil, true)

	withoutPrune, err := planner.Generate(context.Background(), mock, []provider.DesiredSecret{}, planner.Options{Prune: false})
	if err != nil {
		t.Fatal(err)
	}
	if withoutPrune.Stats.Destroy != 0 {
		t.Fatalf("destroy without prune = %d", withoutPrune.Stats.Destroy)
	}

	withPrune, err := planner.Generate(context.Background(), mock, []provider.DesiredSecret{}, planner.Options{Prune: true})
	if err != nil {
		t.Fatal(err)
	}
	if withPrune.Stats.Destroy != 1 {
		t.Fatalf("destroy with prune = %d", withPrune.Stats.Destroy)
	}
}

func TestApplyCreateAndTag(t *testing.T) {
	t.Parallel()

	mock := testutil.NewMockProvider()
	plan, err := planner.Generate(context.Background(), mock, []provider.DesiredSecret{
		{Key: "/created", Value: "example-secret-value"},
	}, planner.Options{})
	if err != nil {
		t.Fatal(err)
	}

	stats, err := planner.Apply(context.Background(), mock, plan)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Add != 1 {
		t.Fatalf("add = %d", stats.Add)
	}
	if !mock.IsManaged("/created") {
		t.Fatal("expected management tag")
	}
}
