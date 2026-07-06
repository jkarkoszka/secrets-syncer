package input

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/jkarkoszka/secrets-syncer/internal/provider"
)

const supportedVersion = 1

// Document is the top-level input schema.
type Document struct {
	Version  int             `json:"version" yaml:"version"`
	Provider string          `json:"provider" yaml:"provider"`
	Secrets  []SecretEntry   `json:"secrets" yaml:"secrets"`
}

// SecretEntry is a single secret in the input document.
type SecretEntry struct {
	Key           string            `json:"key" yaml:"key"`
	Value         string            `json:"value" yaml:"value"`
	Description   string            `json:"description,omitempty" yaml:"description,omitempty"`
	EncryptionKey string            `json:"encryption_key,omitempty" yaml:"encryption_key,omitempty"`
	Tags          map[string]string `json:"tags,omitempty" yaml:"tags,omitempty"`
}

// ReadBytes loads raw input from a file path or "-" for stdin.
func ReadBytes(path string) ([]byte, error) {
	return readBytes(path)
}

// Read loads and parses input from a file path or "-" for stdin.
func Read(path string) (*Document, error) {
	data, err := readBytes(path)
	if err != nil {
		return nil, err
	}
	return Parse(data, path)
}

// Parse decodes YAML or JSON input bytes.
func Parse(data []byte, pathHint string) (*Document, error) {
	format, err := detectFormat(data, pathHint)
	if err != nil {
		return nil, err
	}

	var doc Document
	switch format {
	case "json":
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("parse JSON input: %w", err)
		}
	case "yaml":
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("parse YAML input: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported input format")
	}

	return &doc, nil
}

// Validate checks the document against schema rules.
func Validate(doc *Document) error {
	if doc == nil {
		return fmt.Errorf("input document is nil")
	}
	if doc.Version != supportedVersion {
		return fmt.Errorf("unsupported input version %d (supported: %d)", doc.Version, supportedVersion)
	}
	if doc.Provider == "" {
		return fmt.Errorf("input provider is required")
	}
	if len(doc.Secrets) == 0 {
		return fmt.Errorf("input must contain at least one secret")
	}

	seen := make(map[string]struct{}, len(doc.Secrets))
	for i, secret := range doc.Secrets {
		if strings.TrimSpace(secret.Key) == "" {
			return fmt.Errorf("secrets[%d]: key is required", i)
		}
		if secret.Value == "" {
			return fmt.Errorf("secrets[%d] (%s): value is required", i, secret.Key)
		}
		if _, dup := seen[secret.Key]; dup {
			return fmt.Errorf("duplicate secret key: %s", secret.Key)
		}
		seen[secret.Key] = struct{}{}
	}

	return nil
}

// ToDesired converts validated input to provider desired secrets.
func ToDesired(doc *Document) []provider.DesiredSecret {
	out := make([]provider.DesiredSecret, len(doc.Secrets))
	for i, s := range doc.Secrets {
		tags := make(map[string]string, len(s.Tags))
		for k, v := range s.Tags {
			tags[k] = v
		}
		out[i] = provider.DesiredSecret{
			Key:           s.Key,
			Value:         s.Value,
			Description:   s.Description,
			EncryptionKey: s.EncryptionKey,
			Tags:          tags,
		}
	}
	return out
}

func readBytes(path string) ([]byte, error) {
	if path == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("read stdin: %w", err)
		}
		return data, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read input file %s: %w", path, err)
	}
	return data, nil
}

func detectFormat(data []byte, pathHint string) (string, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return "", fmt.Errorf("input is empty")
	}

	ext := strings.ToLower(filepath.Ext(pathHint))
	switch ext {
	case ".json":
		return "json", nil
	case ".yaml", ".yml":
		return "yaml", nil
	}

	if trimmed[0] == '{' || trimmed[0] == '[' {
		return "json", nil
	}
	return "yaml", nil
}
