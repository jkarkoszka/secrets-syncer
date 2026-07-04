package sops_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jkarkoszka/secrets-syncer/internal/sops"
)

type mockDecryptor struct {
	out []byte
	err error
}

func (m *mockDecryptor) Decrypt(_ context.Context, _ string, _ []byte) ([]byte, error) {
	return m.out, m.err
}

func TestCLIDecryptorMissingBinary(t *testing.T) {
	t.Parallel()

	d := &sops.CLIDecryptor{
		LookPath: func(string) (string, error) {
			return "", errors.New("not found")
		},
	}
	_, err := d.Decrypt(context.Background(), "secrets.enc.yaml", nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDecryptorInterface(t *testing.T) {
	t.Parallel()

	var dec sops.Decryptor = &mockDecryptor{out: []byte("version: 1")}
	out, err := dec.Decrypt(context.Background(), "-", []byte("encrypted"))
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "version: 1" {
		t.Fatalf("out = %q", string(out))
	}
}
