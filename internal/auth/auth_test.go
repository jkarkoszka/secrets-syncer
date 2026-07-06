package auth_test

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/jkarkoszka/secrets-syncer/internal/auth"
)

func TestValidateAccountIDEmpty(t *testing.T) {
	t.Parallel()

	err := auth.ValidateAccountID(context.Background(), aws.Config{}, "")
	if err != nil {
		t.Fatalf("error = %q", err.Error())
	}
}

func TestLoadConfigRequiresRegion(t *testing.T) {
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")
	t.Setenv("AWS_CONFIG_FILE", t.TempDir()+"/config")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", t.TempDir()+"/credentials")

	_, err := auth.LoadConfig(context.Background(), auth.Options{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "region is required") {
		t.Fatalf("error = %q", err.Error())
	}
}

func TestAwsumeArgsWithRole(t *testing.T) {
	t.Parallel()

	args := auth.AwsumeArgsForTest("example-source-profile", "arn:aws:iam::000000000000:role/example-access-role", "eu-central-1")
	if len(args) != 7 || args[0] != "--role-arn" {
		t.Fatalf("args = %v", args)
	}
}

func TestAwsumeArgsWithoutRole(t *testing.T) {
	t.Parallel()

	args := auth.AwsumeArgsForTest("example-source-profile", "", "eu-central-1")
	if len(args) != 4 || args[0] != "example-source-profile" {
		t.Fatalf("args = %v", args)
	}
}

func TestAccountFromRoleARN(t *testing.T) {
	t.Parallel()

	got := auth.AccountFromRoleARNForTest("arn:aws:iam::000000000000:role/example-access-role")
	if got != "000000000000" {
		t.Fatalf("account = %q", got)
	}
}
