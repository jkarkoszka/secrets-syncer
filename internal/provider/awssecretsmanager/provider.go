package awssecretsmanager

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
	rgtypes "github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/smithy-go"

	"github.com/jkarkoszka/secrets-syncer/internal/planner"
	"github.com/jkarkoszka/secrets-syncer/internal/provider"
)

// SecretsManagerAPI is the subset of Secrets Manager used by the provider.
type SecretsManagerAPI interface {
	DescribeSecret(ctx context.Context, params *secretsmanager.DescribeSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.DescribeSecretOutput, error)
	GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
	CreateSecret(ctx context.Context, params *secretsmanager.CreateSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error)
	PutSecretValue(ctx context.Context, params *secretsmanager.PutSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error)
	UpdateSecret(ctx context.Context, params *secretsmanager.UpdateSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.UpdateSecretOutput, error)
	TagResource(ctx context.Context, params *secretsmanager.TagResourceInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.TagResourceOutput, error)
	DeleteSecret(ctx context.Context, params *secretsmanager.DeleteSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.DeleteSecretOutput, error)
}

// TaggingAPI is the subset of Resource Groups Tagging API used by the provider.
type TaggingAPI interface {
	GetResources(ctx context.Context, params *resourcegroupstaggingapi.GetResourcesInput, optFns ...func(*resourcegroupstaggingapi.Options)) (*resourcegroupstaggingapi.GetResourcesOutput, error)
}

// Provider implements provider.SecretProvider for AWS Secrets Manager.
type Provider struct {
	sm   SecretsManagerAPI
	tags TaggingAPI
}

// New creates a Provider from AWS clients.
func New(sm SecretsManagerAPI, tags TaggingAPI) *Provider {
	return &Provider{sm: sm, tags: tags}
}

// DescribeSecret returns metadata for a secret or nil if it does not exist.
func (p *Provider) DescribeSecret(ctx context.Context, key string) (*provider.RemoteSecret, error) {
	out, err := p.sm.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{
		SecretId: aws.String(key),
	})
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	tags := tagsToMap(out.Tags)
	return &provider.RemoteSecret{
		Key:           key,
		Managed:       provider.IsManaged(tags),
		Description:   aws.ToString(out.Description),
		EncryptionKey: aws.ToString(out.KmsKeyId),
		Tags:          tags,
	}, nil
}

// ListManagedSecrets returns secrets tagged with secrets_syncer_managed=true.
func (p *Provider) ListManagedSecrets(ctx context.Context) ([]provider.RemoteSecret, error) {
	if p.tags == nil {
		return nil, fmt.Errorf("tagging API client is not configured")
	}

	var resources []provider.RemoteSecret
	paginator := resourcegroupstaggingapi.NewGetResourcesPaginator(p.tags, &resourcegroupstaggingapi.GetResourcesInput{
		TagFilters: []rgtypes.TagFilter{
			{
				Key:    aws.String(provider.ManagedTagKey),
				Values: []string{provider.ManagedTagValue},
			},
		},
		ResourceTypeFilters: []string{"secretsmanager:secret"},
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, mapping := range page.ResourceTagMappingList {
			key, err := secretKeyFromARN(aws.ToString(mapping.ResourceARN))
			if err != nil {
				return nil, err
			}
			remote, err := p.DescribeSecret(ctx, key)
			if err != nil {
				return nil, err
			}
			if remote != nil && remote.Managed {
				resources = append(resources, *remote)
			}
		}
	}

	return resources, nil
}

// GetSecretValue fetches the secret value.
func (p *Provider) GetSecretValue(ctx context.Context, key string) (*provider.RemoteSecretValue, error) {
	out, err := p.sm.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(key),
	})
	if err != nil {
		return nil, err
	}

	value := aws.ToString(out.SecretString)
	if value == "" && len(out.SecretBinary) > 0 {
		return nil, fmt.Errorf("binary secrets are not supported for %s", key)
	}

	return &provider.RemoteSecretValue{Key: key, Value: value}, nil
}

// CreateSecret creates a new secret with the management tag.
func (p *Provider) CreateSecret(ctx context.Context, desired provider.DesiredSecret) error {
	tags := planner.MergeTags(desired.Tags)
	smTags := mapToTags(tags)

	input := &secretsmanager.CreateSecretInput{
		Name:         aws.String(desired.Key),
		SecretString: aws.String(desired.Value),
		Tags:         smTags,
	}
	if desired.Description != "" {
		input.Description = aws.String(desired.Description)
	}
	if desired.EncryptionKey != "" {
		input.KmsKeyId = aws.String(desired.EncryptionKey)
	}

	_, err := p.sm.CreateSecret(ctx, input)
	return err
}

// UpdateSecret updates value and metadata for a managed secret.
func (p *Provider) UpdateSecret(ctx context.Context, desired provider.DesiredSecret) error {
	if _, err := p.sm.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{
		SecretId:     aws.String(desired.Key),
		SecretString: aws.String(desired.Value),
	}); err != nil {
		return err
	}

	updateInput := &secretsmanager.UpdateSecretInput{
		SecretId: aws.String(desired.Key),
	}
	if desired.Description != "" {
		updateInput.Description = aws.String(desired.Description)
	}
	if desired.EncryptionKey != "" {
		updateInput.KmsKeyId = aws.String(desired.EncryptionKey)
	}

	if updateInput.Description != nil || updateInput.KmsKeyId != nil {
		if _, err := p.sm.UpdateSecret(ctx, updateInput); err != nil {
			return err
		}
	}

	tags := planner.MergeTags(desired.Tags)
	_, err := p.sm.TagResource(ctx, &secretsmanager.TagResourceInput{
		SecretId: aws.String(desired.Key),
		Tags:     mapToTags(tags),
	})
	return err
}

// DeleteSecret removes a managed secret.
func (p *Provider) DeleteSecret(ctx context.Context, key string) error {
	_, err := p.sm.DeleteSecret(ctx, &secretsmanager.DeleteSecretInput{
		SecretId:                   aws.String(key),
		ForceDeleteWithoutRecovery: aws.Bool(true),
	})
	return err
}

func isNotFound(err error) bool {
	var notFound *smtypes.ResourceNotFoundException
	return errors.As(err, &notFound)
}

func tagsToMap(tags []smtypes.Tag) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		out[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
	}
	return out
}

func mapToTags(tags map[string]string) []smtypes.Tag {
	out := make([]smtypes.Tag, 0, len(tags))
	for k, v := range tags {
		out = append(out, smtypes.Tag{Key: aws.String(k), Value: aws.String(v)})
	}
	return out
}

func secretKeyFromARN(arn string) (string, error) {
	if arn == "" {
		return "", fmt.Errorf("empty secret ARN")
	}
	// arn:aws:secretsmanager:region:account:secret:name-6RandomChars
	const prefix = ":secret:"
	idx := strings.Index(arn, prefix)
	if idx < 0 {
		return "", fmt.Errorf("invalid secrets manager ARN: %s", arn)
	}
	nameWithSuffix := arn[idx+len(prefix):]
	if dash := strings.LastIndex(nameWithSuffix, "-"); dash > 0 {
		return nameWithSuffix[:dash], nil
	}
	return nameWithSuffix, nil
}

// Ensure smithy import is used for API error checks in tests.
var _ smithy.APIError = (*smtypes.ResourceNotFoundException)(nil)
