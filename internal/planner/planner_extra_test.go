package planner_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jkarkoszka/secrets-syncer/internal/planner"
	"github.com/jkarkoszka/secrets-syncer/internal/provider"
	"github.com/jkarkoszka/secrets-syncer/internal/testutil"
)

func TestPlanDeleteDoesNotHappenWithoutPrune(t *testing.T) {
	mock := testutil.NewMockProvider()
	mock.Seed("/orphan", "value", "", "", nil, true)

	plan, err := planner.Generate(context.Background(), mock, []provider.DesiredSecret{}, planner.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Stats.Destroy != 0 {
		t.Fatalf("destroy = %d", plan.Stats.Destroy)
	}
}

func TestPlanDeleteWithPruneOnlyManaged(t *testing.T) {
	mock := testutil.NewMockProvider()
	mock.Seed("/managed-orphan", "value", "", "", nil, true)
	mock.Seed("/unmanaged-orphan", "value", "", "", nil, false)

	plan, err := planner.Generate(context.Background(), mock, []provider.DesiredSecret{}, planner.Options{Prune: true})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Stats.Destroy != 1 {
		t.Fatalf("destroy = %d", plan.Stats.Destroy)
	}
	if plan.Actions[0].Key != "/managed-orphan" {
		t.Fatalf("deleted key = %s", plan.Actions[0].Key)
	}
}

func TestPlanDescriptionChange(t *testing.T) {
	mock := testutil.NewMockProvider()
	mock.Seed("/desc", "same-value", "old-desc", "", nil, true)

	plan, err := planner.Generate(context.Background(), mock, []provider.DesiredSecret{
		{Key: "/desc", Value: "same-value", Description: "new-desc"},
	}, planner.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Stats.Change != 1 {
		t.Fatalf("change = %d", plan.Stats.Change)
	}
}

func TestErrorMessagesDoNotContainSecretValue(t *testing.T) {
	mock := testutil.NewMockProvider()
	secretValue := "super-secret-test-value-12345"

	_, err := planner.Generate(context.Background(), mock, []provider.DesiredSecret{
		{Key: "/missing", Value: secretValue},
	}, planner.Options{})
	if err != nil {
		if strings.Contains(err.Error(), secretValue) {
			t.Fatal("secret value leaked into error message")
		}
	}
}
