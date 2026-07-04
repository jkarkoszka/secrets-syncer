package sops

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
)

// Decryptor decrypts SOPS-encrypted content.
type Decryptor interface {
	Decrypt(ctx context.Context, inputPath string, data []byte) ([]byte, error)
}

// CLIDecryptor shells out to the sops binary.
type CLIDecryptor struct {
	LookPath func(string) (string, error)
}

// NewCLIDecryptor creates a decryptor that uses the sops CLI.
func NewCLIDecryptor() *CLIDecryptor {
	return &CLIDecryptor{LookPath: exec.LookPath}
}

// Decrypt runs sops -d on a file path or stdin content.
func (d *CLIDecryptor) Decrypt(ctx context.Context, inputPath string, data []byte) ([]byte, error) {
	bin, err := d.LookPath("sops")
	if err != nil {
		return nil, fmt.Errorf("sops not found on PATH: install sops or decrypt input before piping")
	}

	var cmd *exec.Cmd
	if inputPath != "-" {
		cmd = exec.CommandContext(ctx, bin, "-d", inputPath)
		cmd.Env = os.Environ()
	} else {
		cmd = exec.CommandContext(ctx, bin, "-d", "/dev/stdin")
		cmd.Env = os.Environ()
		cmd.Stdin = bytes.NewReader(data)
	}

	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("sops decrypt failed: %w", err)
	}
	return stdout.Bytes(), nil
}
