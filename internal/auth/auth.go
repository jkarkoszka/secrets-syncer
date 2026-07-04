package auth

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// Options configure AWS authentication.
type Options struct {
	Region  string
	Profile string
	RoleARN string
}

// LoadConfig resolves AWS credentials and returns an aws.Config.
//
// Credential resolution order:
//  1. Environment variables (AWS_ACCESS_KEY_ID, etc.) — takes precedence over --profile
//     so an active awsume session is not discarded when --profile is also passed.
//  2. --profile with awsume on PATH — MFA + optional role assumption via awsume.
//  3. --profile via AWS SDK shared config.
//  4. Default AWS credential chain.
//
// When --role-arn is set, the role is assumed unless the active credentials are
// already for that role's account (e.g. after awsume into the target account).
func LoadConfig(ctx context.Context, opts Options) (aws.Config, error) {
	if opts.Region == "" {
		return aws.Config{}, fmt.Errorf("region is required")
	}

	creds, source, err := resolveCredentials(ctx, opts)
	if err != nil {
		return aws.Config{}, err
	}

	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(opts.Region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			creds.AccessKeyID,
			creds.SecretAccessKey,
			creds.SessionToken,
		)),
	)
	if err != nil {
		return aws.Config{}, fmt.Errorf("load AWS config: %w", err)
	}

	if opts.RoleARN != "" && !alreadyInRoleAccount(ctx, cfg, opts.RoleARN) {
		if source == sourceProfileAwsume {
			return aws.Config{}, fmt.Errorf("awsume did not return credentials for role %s", opts.RoleARN)
		}
		cfg, err = withAssumedRole(ctx, cfg, opts.RoleARN)
		if err != nil {
			return aws.Config{}, fmt.Errorf("assume role %s: %w", opts.RoleARN, err)
		}
	}

	return cfg, nil
}

type credentialSource int

const (
	sourceEnvironment credentialSource = iota
	sourceProfileAwsume
	sourceProfileSDK
	sourceDefaultChain
)

func resolveCredentials(ctx context.Context, opts Options) (sessionCredentials, credentialSource, error) {
	if creds, ok := credentialsFromEnv(opts.Region); ok {
		return creds, sourceEnvironment, nil
	}

	if opts.Profile != "" {
		if creds, err := credentialsFromAwsume(ctx, opts.Profile, opts.RoleARN, opts.Region); err == nil {
			return creds, sourceProfileAwsume, nil
		} else if !isAwsumeMissing(err) {
			return sessionCredentials{}, 0, err
		}

		cfg, err := config.LoadDefaultConfig(ctx,
			config.WithRegion(opts.Region),
			config.WithSharedConfigProfile(opts.Profile),
		)
		if err != nil {
			return sessionCredentials{}, 0, fmt.Errorf("load AWS profile %q: %w", opts.Profile, err)
		}
		value, err := cfg.Credentials.Retrieve(ctx)
		if err != nil {
			return sessionCredentials{}, 0, fmt.Errorf("retrieve credentials for profile %q: %w", opts.Profile, err)
		}
		return sessionCredentials{
			AccessKeyID:     value.AccessKeyID,
			SecretAccessKey: value.SecretAccessKey,
			SessionToken:    value.SessionToken,
			Region:          opts.Region,
		}, sourceProfileSDK, nil
	}

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(opts.Region))
	if err != nil {
		return sessionCredentials{}, 0, fmt.Errorf("load default AWS config: %w", err)
	}
	value, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return sessionCredentials{}, 0, fmt.Errorf("retrieve default credentials: %w", err)
	}
	return sessionCredentials{
		AccessKeyID:     value.AccessKeyID,
		SecretAccessKey: value.SecretAccessKey,
		SessionToken:    value.SessionToken,
		Region:          opts.Region,
	}, sourceDefaultChain, nil
}

func isAwsumeMissing(err error) bool {
	return err != nil && strings.Contains(err.Error(), "not found on PATH")
}

func alreadyInRoleAccount(ctx context.Context, cfg aws.Config, roleARN string) bool {
	targetAccount := accountFromRoleARN(roleARN)
	if targetAccount == "" {
		return false
	}
	client := sts.NewFromConfig(cfg)
	out, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return false
	}
	return aws.ToString(out.Account) == targetAccount
}

func withAssumedRole(ctx context.Context, cfg aws.Config, roleARN string) (aws.Config, error) {
	stsClient := sts.NewFromConfig(cfg)
	provider := stscreds.NewAssumeRoleProvider(stsClient, roleARN, func(o *stscreds.AssumeRoleOptions) {
		o.TokenProvider = stscreds.StdinTokenProvider
	})
	cfg.Credentials = aws.NewCredentialsCache(provider)
	return cfg, nil
}

// ValidateAccountID checks that the active credentials belong to the expected account.
func ValidateAccountID(ctx context.Context, cfg aws.Config, expectedAccountID string) error {
	if expectedAccountID == "" {
		return fmt.Errorf("account-id is required")
	}

	client := sts.NewFromConfig(cfg)
	out, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return fmt.Errorf("get caller identity: %w", err)
	}

	actual := aws.ToString(out.Account)
	if actual != expectedAccountID {
		return fmt.Errorf("account mismatch: expected %s, got %s", expectedAccountID, actual)
	}
	return nil
}
