package testutil

import (
	"context"
	"fmt"
	"sync"

	"github.com/jkarkoszka/secrets-syncer/internal/provider"
)

// MockProvider is an in-memory SecretProvider for tests.
type MockProvider struct {
	mu      sync.Mutex
	secrets map[string]mockSecret
}

type mockSecret struct {
	meta  provider.RemoteSecret
	value string
}

// NewMockProvider creates an empty mock provider.
func NewMockProvider() *MockProvider {
	return &MockProvider{secrets: make(map[string]mockSecret)}
}

// Seed adds or replaces a secret in the mock store.
func (m *MockProvider) Seed(key, value, description, encryptionKey string, tags map[string]string, managed bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	tagCopy := make(map[string]string, len(tags))
	for k, v := range tags {
		tagCopy[k] = v
	}
	if managed {
		tagCopy[provider.ManagedTagKey] = provider.ManagedTagValue
	}

	m.secrets[key] = mockSecret{
		meta: provider.RemoteSecret{
			Key:           key,
			Managed:       managed,
			Description:   description,
			EncryptionKey: encryptionKey,
			Tags:          tagCopy,
		},
		value: value,
	}
}

func (m *MockProvider) DescribeSecret(_ context.Context, key string) (*provider.RemoteSecret, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	secret, ok := m.secrets[key]
	if !ok {
		return nil, nil
	}
	meta := secret.meta
	return &meta, nil
}

func (m *MockProvider) ListManagedSecrets(_ context.Context) ([]provider.RemoteSecret, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var out []provider.RemoteSecret
	for _, secret := range m.secrets {
		if secret.meta.Managed {
			out = append(out, secret.meta)
		}
	}
	return out, nil
}

func (m *MockProvider) GetSecretValue(_ context.Context, key string) (*provider.RemoteSecretValue, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	secret, ok := m.secrets[key]
	if !ok {
		return nil, fmt.Errorf("secret not found: %s", key)
	}
	return &provider.RemoteSecretValue{Key: key, Value: secret.value}, nil
}

func (m *MockProvider) CreateSecret(_ context.Context, desired provider.DesiredSecret) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.secrets[desired.Key]; exists {
		return fmt.Errorf("secret already exists: %s", desired.Key)
	}

	tags := make(map[string]string, len(desired.Tags)+1)
	for k, v := range desired.Tags {
		tags[k] = v
	}
	tags[provider.ManagedTagKey] = provider.ManagedTagValue

	m.secrets[desired.Key] = mockSecret{
		meta: provider.RemoteSecret{
			Key:           desired.Key,
			Managed:       true,
			Description:   desired.Description,
			EncryptionKey: desired.EncryptionKey,
			Tags:          tags,
		},
		value: desired.Value,
	}
	return nil
}

func (m *MockProvider) UpdateSecret(_ context.Context, desired provider.DesiredSecret) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	secret, ok := m.secrets[desired.Key]
	if !ok {
		return fmt.Errorf("secret not found: %s", desired.Key)
	}
	if !secret.meta.Managed {
		return fmt.Errorf("secret is not managed: %s", desired.Key)
	}

	tags := make(map[string]string, len(desired.Tags)+1)
	for k, v := range desired.Tags {
		tags[k] = v
	}
	tags[provider.ManagedTagKey] = provider.ManagedTagValue

	secret.value = desired.Value
	secret.meta.Description = desired.Description
	if desired.EncryptionKey != "" {
		secret.meta.EncryptionKey = desired.EncryptionKey
	}
	secret.meta.Tags = tags
	m.secrets[desired.Key] = secret
	return nil
}

func (m *MockProvider) DeleteSecret(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	secret, ok := m.secrets[key]
	if !ok {
		return fmt.Errorf("secret not found: %s", key)
	}
	if !secret.meta.Managed {
		return fmt.Errorf("secret is not managed: %s", key)
	}
	delete(m.secrets, key)
	return nil
}

// GetValue returns the stored value for assertions in tests.
func (m *MockProvider) GetValue(key string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	secret, ok := m.secrets[key]
	if !ok {
		return "", false
	}
	return secret.value, true
}

// IsManaged reports whether the secret has the management tag.
func (m *MockProvider) IsManaged(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	secret, ok := m.secrets[key]
	return ok && secret.meta.Managed
}
