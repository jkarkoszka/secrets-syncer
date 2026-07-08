package cli_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jkarkoszka/secrets-syncer/internal/auth"
	"github.com/jkarkoszka/secrets-syncer/internal/cli"
	"github.com/jkarkoszka/secrets-syncer/internal/config"
	"github.com/jkarkoszka/secrets-syncer/internal/output"
	"github.com/jkarkoszka/secrets-syncer/internal/provider"
	"github.com/jkarkoszka/secrets-syncer/internal/testutil"
)

func TestValidateCommand(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "secrets.yaml")
	cli.SetRunConfig(config.RunConfig{
		InputPath: path,
	})
	t.Cleanup(cli.ResetRunConfig)

	buf := &bytes.Buffer{}
	output.SetWriter(buf)
	t.Cleanup(output.ResetWriter)

	root := cli.RootCommand()
	root.SetArgs([]string{"validate"})

	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "Success!") {
		t.Fatalf("output = %q", buf.String())
	}
}

func TestPlanWithMockProvider(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "secrets.yaml")
	mock := testutil.NewMockProvider()

	cli.SetRunConfig(config.RunConfig{
		InputPath: path,
		AccountID: "000000000000",
		Region:    "eu-central-1",
		NoColor:   true,
	})
	cli.SetProviderFactory(func(_ context.Context, _ config.RunConfig) (provider.SecretProvider, *auth.Identity, error) {
		return mock, nil, nil
	})
	t.Cleanup(func() {
		cli.ResetProviderFactory()
		cli.ResetRunConfig()
	})

	buf := &bytes.Buffer{}
	output.SetWriter(buf)
	t.Cleanup(output.ResetWriter)

	root := cli.RootCommand()
	root.SetArgs([]string{"plan"})

	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "Plan: 2 to add, 0 to change, 0 to destroy.") {
		t.Fatalf("output = %q", out)
	}
	if strings.Contains(out, "example-secret-value") || strings.Contains(out, "another-secret-value") {
		t.Fatal("secret values leaked in CLI output")
	}
}

func TestPlanStdinInput(t *testing.T) {
	mock := testutil.NewMockProvider()
	inputData := []byte("version: 1\nprovider: aws-secretsmanager\nsecrets:\n  - key: /stdin\n    value: stdin-secret-value\n")

	cli.SetRunConfig(config.RunConfig{
		InputPath: "-",
		AccountID: "000000000000",
		Region:    "eu-central-1",
		NoColor:   true,
	})
	cli.SetProviderFactory(func(_ context.Context, _ config.RunConfig) (provider.SecretProvider, *auth.Identity, error) {
		return mock, nil, nil
	})
	cli.SetStdinReader(bytes.NewReader(inputData))
	t.Cleanup(func() {
		cli.ResetProviderFactory()
		cli.ResetStdinReader()
		cli.ResetRunConfig()
	})

	buf := &bytes.Buffer{}
	output.SetWriter(buf)
	t.Cleanup(output.ResetWriter)

	root := cli.RootCommand()
	root.SetArgs([]string{"plan"})

	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "Plan: 1 to add") {
		t.Fatalf("output = %q", buf.String())
	}
}

func TestPlanInputEnv(t *testing.T) {
	mock := testutil.NewMockProvider()
	inputData := `{"version":1,"provider":"aws-secretsmanager","secrets":[{"key":"/env","value":"env-secret"}]}`

	t.Setenv("SECRETS_SYNCER_INPUT", inputData)
	cli.SetRunConfig(config.RunConfig{
		InputEnv:  "SECRETS_SYNCER_INPUT",
		AccountID: "000000000000",
		Region:    "eu-central-1",
		NoColor:   true,
	})
	cli.SetProviderFactory(func(_ context.Context, _ config.RunConfig) (provider.SecretProvider, *auth.Identity, error) {
		return mock, nil, nil
	})
	t.Cleanup(func() {
		cli.ResetProviderFactory()
		cli.ResetRunConfig()
	})

	buf := &bytes.Buffer{}
	output.SetWriter(buf)
	t.Cleanup(output.ResetWriter)

	root := cli.RootCommand()
	root.SetArgs([]string{"plan"})

	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "Plan: 1 to add") {
		t.Fatalf("output = %q", buf.String())
	}
}

func TestApplyStdinInputWithTTYConfirmation(t *testing.T) {
	mock := testutil.NewMockProvider()
	inputData := []byte("version: 1\nprovider: aws-secretsmanager\nsecrets:\n  - key: /stdin-apply\n    value: apply-secret-value\n")

	cli.SetRunConfig(config.RunConfig{
		InputPath: "-",
		AccountID: "000000000000",
		Region:    "eu-central-1",
		NoColor:   true,
	})
	cli.SetProviderFactory(func(_ context.Context, _ config.RunConfig) (provider.SecretProvider, *auth.Identity, error) {
		return mock, nil, nil
	})
	cli.SetStdinReader(bytes.NewReader(inputData))
	cli.SetOpenTTY(func(string) (*os.File, error) {
		r, w, err := os.Pipe()
		if err != nil {
			return nil, err
		}
		_, _ = w.WriteString("yes\n")
		_ = w.Close()
		return r, nil
	})
	t.Cleanup(func() {
		cli.ResetProviderFactory()
		cli.ResetStdinReader()
		cli.ResetOpenTTY()
		cli.ResetRunConfig()
	})

	buf := &bytes.Buffer{}
	output.SetWriter(buf)
	t.Cleanup(output.ResetWriter)

	root := cli.RootCommand()
	root.SetArgs([]string{"apply"})

	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if !mock.IsManaged("/stdin-apply") {
		t.Fatal("secret was not created")
	}
}

func TestApplyAutoApprove(t *testing.T) {
	mock := testutil.NewMockProvider()
	inputData := []byte("version: 1\nprovider: aws-secretsmanager\nsecrets:\n  - key: /apply\n    value: apply-secret-value\n")

	cli.SetRunConfig(config.RunConfig{
		InputPath:   "-",
		AccountID:   "000000000000",
		Region:      "eu-central-1",
		AutoApprove: true,
		NoColor:     true,
	})
	cli.SetProviderFactory(func(_ context.Context, _ config.RunConfig) (provider.SecretProvider, *auth.Identity, error) {
		return mock, nil, nil
	})
	cli.SetStdinReader(bytes.NewReader(inputData))
	t.Cleanup(func() {
		cli.ResetProviderFactory()
		cli.ResetStdinReader()
		cli.ResetRunConfig()
	})

	buf := &bytes.Buffer{}
	output.SetWriter(buf)
	t.Cleanup(output.ResetWriter)

	root := cli.RootCommand()
	root.SetArgs([]string{"apply"})

	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if !mock.IsManaged("/apply") {
		t.Fatal("secret was not created with management tag")
	}
	if strings.Contains(buf.String(), "apply-secret-value") {
		t.Fatal("secret value leaked in apply output")
	}
}

func TestSOPSFlagUsesDecryptor(t *testing.T) {
	mock := testutil.NewMockProvider()
	plaintext := []byte("version: 1\nprovider: aws-secretsmanager\nsecrets:\n  - key: /sops\n    value: sops-secret-value\n")

	cli.SetRunConfig(config.RunConfig{
		InputPath: "secrets.enc.yaml",
		SOPS:      true,
		AccountID: "000000000000",
		Region:    "eu-central-1",
		NoColor:   true,
	})
	cli.SetDecryptor(&mockSOPSDecryptor{out: plaintext})
	cli.SetProviderFactory(func(_ context.Context, _ config.RunConfig) (provider.SecretProvider, *auth.Identity, error) {
		return mock, nil, nil
	})
	t.Cleanup(func() {
		cli.ResetDecryptor()
		cli.ResetProviderFactory()
		cli.ResetRunConfig()
	})

	buf := &bytes.Buffer{}
	output.SetWriter(buf)
	t.Cleanup(output.ResetWriter)

	root := cli.RootCommand()
	root.SetArgs([]string{"plan"})

	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "Plan: 1 to add") {
		t.Fatalf("output = %q", buf.String())
	}
}

func TestPlanConflictExit(t *testing.T) {
	mock := testutil.NewMockProvider()
	mock.Seed("/dev1/networking/bgp_auth_key", "old", "", "", nil, false)

	path := filepath.Join("..", "..", "testdata", "secrets.yaml")
	cli.SetRunConfig(config.RunConfig{
		InputPath: path,
		AccountID: "000000000000",
		Region:    "eu-central-1",
		NoColor:   true,
	})
	cli.SetProviderFactory(func(_ context.Context, _ config.RunConfig) (provider.SecretProvider, *auth.Identity, error) {
		return mock, nil, nil
	})
	t.Cleanup(func() {
		cli.ResetProviderFactory()
		cli.ResetRunConfig()
	})

	buf := &bytes.Buffer{}
	output.SetWriter(buf)
	t.Cleanup(output.ResetWriter)

	root := cli.RootCommand()
	root.SetArgs([]string{"plan"})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected conflict error")
	}
	if !strings.Contains(buf.String(), "not managed by secrets-syncer") {
		t.Fatalf("output = %q", buf.String())
	}
}

func TestPlanEmptyWithPrune(t *testing.T) {
	mock := testutil.NewMockProvider()
	mock.Seed("/managed/delete", "v", "", "", nil, true)

	inputData := []byte("version: 1\nprovider: aws-secretsmanager\nsecrets: []\n")
	cli.SetRunConfig(config.RunConfig{
		InputPath: "-",
		AccountID: "000000000000",
		Region:    "eu-central-1",
		NoColor:   true,
		Prune:     true,
	})
	cli.SetProviderFactory(func(_ context.Context, _ config.RunConfig) (provider.SecretProvider, *auth.Identity, error) {
		return mock, nil, nil
	})
	cli.SetStdinReader(bytes.NewReader(inputData))
	t.Cleanup(func() {
		cli.ResetProviderFactory()
		cli.ResetStdinReader()
		cli.ResetRunConfig()
	})

	buf := &bytes.Buffer{}
	output.SetWriter(buf)
	t.Cleanup(output.ResetWriter)

	root := cli.RootCommand()
	root.SetArgs([]string{"plan", "--prune"})

	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "destroy /managed/delete") {
		t.Fatalf("output = %q", buf.String())
	}
}

type mockSOPSDecryptor struct {
	out []byte
}

func (m *mockSOPSDecryptor) Decrypt(_ context.Context, _ string, _ []byte) ([]byte, error) {
	return m.out, nil
}
