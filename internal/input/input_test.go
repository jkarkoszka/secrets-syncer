package input_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jkarkoszka/secrets-syncer/internal/input"
	"github.com/jkarkoszka/secrets-syncer/internal/provider"
)

func TestParseYAML(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "secrets.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	doc, err := input.Parse(data, "secrets.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if doc.Version != 1 {
		t.Fatalf("version = %d", doc.Version)
	}
	if len(doc.Secrets) != 2 {
		t.Fatalf("secrets = %d", len(doc.Secrets))
	}
}

func TestParseJSON(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "secrets.json"))
	if err != nil {
		t.Fatal(err)
	}

	doc, err := input.Parse(data, "secrets.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Secrets) != 1 {
		t.Fatalf("secrets = %d", len(doc.Secrets))
	}
}

func TestParseStdinStylePath(t *testing.T) {
	t.Parallel()

	doc, err := input.Parse([]byte("version: 1\nprovider: aws-secretsmanager\nsecrets:\n  - key: /a\n    value: v\n"), "-")
	if err != nil {
		t.Fatal(err)
	}
	if doc.Secrets[0].Key != "/a" {
		t.Fatalf("key = %q", doc.Secrets[0].Key)
	}
}

func TestValidateErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		doc  input.Document
		err  string
	}{
		{
			name: "missing key",
			doc: input.Document{
				Version:  1,
				Provider: provider.ProviderAWS,
				Secrets:  []input.SecretEntry{{Value: "x"}},
			},
			err: "key is required",
		},
		{
			name: "missing value",
			doc: input.Document{
				Version:  1,
				Provider: provider.ProviderAWS,
				Secrets:  []input.SecretEntry{{Key: "/a"}},
			},
			err: "value is required",
		},
		{
			name: "duplicate key",
			doc: input.Document{
				Version:  1,
				Provider: provider.ProviderAWS,
				Secrets: []input.SecretEntry{
					{Key: "/a", Value: "1"},
					{Key: "/a", Value: "2"},
				},
			},
			err: "duplicate secret key",
		},
		{
			name: "provider mismatch",
			doc: input.Document{
				Version:  1,
				Provider: "vault",
				Secrets:  []input.SecretEntry{{Key: "/a", Value: "1"}},
			},
			err: "does not match",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := input.Validate(&tc.doc, provider.ProviderAWS)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.err) {
				t.Fatalf("error = %q", err.Error())
			}
		})
	}
}

func TestReadFromFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "testdata", "secrets.yaml")
	doc, err := input.Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := input.Validate(doc, provider.ProviderAWS); err != nil {
		t.Fatal(err)
	}
}

func TestToDesired(t *testing.T) {
	t.Parallel()

	doc := &input.Document{
		Version:  1,
		Provider: provider.ProviderAWS,
		Secrets: []input.SecretEntry{
			{Key: "/a", Value: "secret-value", Tags: map[string]string{"env": "dev"}},
		},
	}
	desired := input.ToDesired(doc)
	if desired[0].Value != "secret-value" {
		t.Fatalf("value leaked in test assertion context")
	}
}
