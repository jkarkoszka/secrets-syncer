package provider

import "context"

const (
	ManagedTagKey   = "secrets_syncer_managed"
	ManagedTagValue = "true"
	ProviderAWS     = "aws-secretsmanager"
)

// DesiredSecret is the desired state for a single secret.
type DesiredSecret struct {
	Key           string
	Value         string
	Description   string
	EncryptionKey string
	Tags          map[string]string
}

// RemoteSecret describes a secret in the remote provider without its value.
type RemoteSecret struct {
	Key           string
	Managed       bool
	Description   string
	EncryptionKey string
	Tags          map[string]string
}

// RemoteSecretValue is a secret value fetched from the remote provider.
type RemoteSecretValue struct {
	Key   string
	Value string
}

// SecretProvider abstracts secret backends.
type SecretProvider interface {
	DescribeSecret(ctx context.Context, key string) (*RemoteSecret, error)
	ListManagedSecrets(ctx context.Context) ([]RemoteSecret, error)
	GetSecretValue(ctx context.Context, key string) (*RemoteSecretValue, error)
	CreateSecret(ctx context.Context, desired DesiredSecret) error
	UpdateSecret(ctx context.Context, desired DesiredSecret) error
	DeleteSecret(ctx context.Context, key string) error
}

// IsManaged reports whether tags indicate secrets-syncer management.
func IsManaged(tags map[string]string) bool {
	return tags != nil && tags[ManagedTagKey] == ManagedTagValue
}
