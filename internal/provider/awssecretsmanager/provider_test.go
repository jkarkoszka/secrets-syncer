package awssecretsmanager_test

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
	rgtypes "github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"

	"github.com/jkarkoszka/secrets-syncer/internal/planner"
	"github.com/jkarkoszka/secrets-syncer/internal/provider"
	"github.com/jkarkoszka/secrets-syncer/internal/provider/awssecretsmanager"
)

type fakeSM struct {
	secrets map[string]fakeSecret
}

type fakeSecret struct {
	value       string
	description string
	kmsKeyID    string
	tags        map[string]string
}

func newFakeSM() *fakeSM {
	return &fakeSM{secrets: make(map[string]fakeSecret)}
}

func (f *fakeSM) DescribeSecret(_ context.Context, params *secretsmanager.DescribeSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.DescribeSecretOutput, error) {
	name := aws.ToString(params.SecretId)
	secret, ok := f.secrets[name]
	if !ok {
		return nil, &smtypes.ResourceNotFoundException{}
	}
	return &secretsmanager.DescribeSecretOutput{
		Name:        aws.String(name),
		Description: aws.String(secret.description),
		KmsKeyId:    aws.String(secret.kmsKeyID),
		Tags:        toSMTags(secret.tags),
	}, nil
}

func (f *fakeSM) GetSecretValue(_ context.Context, params *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	name := aws.ToString(params.SecretId)
	secret, ok := f.secrets[name]
	if !ok {
		return nil, &smtypes.ResourceNotFoundException{}
	}
	return &secretsmanager.GetSecretValueOutput{SecretString: aws.String(secret.value)}, nil
}

func (f *fakeSM) CreateSecret(_ context.Context, params *secretsmanager.CreateSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error) {
	name := aws.ToString(params.Name)
	f.secrets[name] = fakeSecret{
		value:       aws.ToString(params.SecretString),
		description: aws.ToString(params.Description),
		kmsKeyID:    aws.ToString(params.KmsKeyId),
		tags:        fromSMTags(params.Tags),
	}
	return &secretsmanager.CreateSecretOutput{}, nil
}

func (f *fakeSM) PutSecretValue(_ context.Context, params *secretsmanager.PutSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error) {
	name := aws.ToString(params.SecretId)
	secret, ok := f.secrets[name]
	if !ok {
		return nil, &smtypes.ResourceNotFoundException{}
	}
	secret.value = aws.ToString(params.SecretString)
	f.secrets[name] = secret
	return &secretsmanager.PutSecretValueOutput{}, nil
}

func (f *fakeSM) UpdateSecret(_ context.Context, params *secretsmanager.UpdateSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.UpdateSecretOutput, error) {
	name := aws.ToString(params.SecretId)
	secret, ok := f.secrets[name]
	if !ok {
		return nil, &smtypes.ResourceNotFoundException{}
	}
	if params.Description != nil {
		secret.description = aws.ToString(params.Description)
	}
	if params.KmsKeyId != nil {
		secret.kmsKeyID = aws.ToString(params.KmsKeyId)
	}
	f.secrets[name] = secret
	return &secretsmanager.UpdateSecretOutput{}, nil
}

func (f *fakeSM) TagResource(_ context.Context, params *secretsmanager.TagResourceInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.TagResourceOutput, error) {
	name := aws.ToString(params.SecretId)
	secret, ok := f.secrets[name]
	if !ok {
		return nil, &smtypes.ResourceNotFoundException{}
	}
	for _, tag := range params.Tags {
		if secret.tags == nil {
			secret.tags = make(map[string]string)
		}
		secret.tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
	}
	f.secrets[name] = secret
	return &secretsmanager.TagResourceOutput{}, nil
}

func (f *fakeSM) DeleteSecret(_ context.Context, params *secretsmanager.DeleteSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.DeleteSecretOutput, error) {
	name := aws.ToString(params.SecretId)
	if _, ok := f.secrets[name]; !ok {
		return nil, &smtypes.ResourceNotFoundException{}
	}
	delete(f.secrets, name)
	return &secretsmanager.DeleteSecretOutput{}, nil
}

type fakeTagging struct {
	arns []string
}

func (f *fakeTagging) GetResources(_ context.Context, _ *resourcegroupstaggingapi.GetResourcesInput, _ ...func(*resourcegroupstaggingapi.Options)) (*resourcegroupstaggingapi.GetResourcesOutput, error) {
	mappings := make([]rgtypes.ResourceTagMapping, 0, len(f.arns))
	for _, arn := range f.arns {
		mappings = append(mappings, rgtypes.ResourceTagMapping{ResourceARN: aws.String(arn)})
	}
	return &resourcegroupstaggingapi.GetResourcesOutput{ResourceTagMappingList: mappings}, nil
}

func TestProviderCreateSetsManagedTag(t *testing.T) {
	t.Parallel()

	sm := newFakeSM()
	prov := awssecretsmanager.New(sm, &fakeTagging{})

	err := prov.CreateSecret(context.Background(), provider.DesiredSecret{
		Key:   "/dev1/new",
		Value: "example-secret-value",
		Tags:  map[string]string{"env": "dev1"},
	})
	if err != nil {
		t.Fatal(err)
	}

	remote, err := prov.DescribeSecret(context.Background(), "/dev1/new")
	if err != nil {
		t.Fatal(err)
	}
	if !remote.Managed {
		t.Fatal("expected managed tag")
	}
}

func TestProviderDoesNotUpdateUnmanaged(t *testing.T) {
	t.Parallel()

	sm := newFakeSM()
	sm.secrets["/dev1/unmanaged"] = fakeSecret{value: "existing", tags: map[string]string{"env": "dev1"}}
	prov := awssecretsmanager.New(sm, &fakeTagging{})

	remote, err := prov.DescribeSecret(context.Background(), "/dev1/unmanaged")
	if err != nil {
		t.Fatal(err)
	}
	if remote.Managed {
		t.Fatal("expected unmanaged")
	}

	plan, err := planner.Generate(context.Background(), prov, []provider.DesiredSecret{
		{Key: "/dev1/unmanaged", Value: "example-secret-value"},
	}, planner.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.HasConflicts() {
		t.Fatal("expected conflict")
	}
}

func TestProviderListManagedSecrets(t *testing.T) {
	t.Parallel()

	sm := newFakeSM()
	sm.secrets["/managed"] = fakeSecret{
		value: "v",
		tags:  map[string]string{provider.ManagedTagKey: provider.ManagedTagValue},
	}
	prov := awssecretsmanager.New(sm, &fakeTagging{
		arns: []string{"arn:aws:secretsmanager:eu-central-1:000000000000:secret:/managed-abc123"},
	})

	secrets, err := prov.ListManagedSecrets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != 1 || secrets[0].Key != "/managed" {
		t.Fatalf("secrets = %+v", secrets)
	}
}

func toSMTags(tags map[string]string) []smtypes.Tag {
	out := make([]smtypes.Tag, 0, len(tags))
	for k, v := range tags {
		out = append(out, smtypes.Tag{Key: aws.String(k), Value: aws.String(v)})
	}
	return out
}

func fromSMTags(tags []smtypes.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		out[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
	}
	return out
}
