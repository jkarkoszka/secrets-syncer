package auth

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

var exportLine = regexp.MustCompile(`^export\s+([A-Za-z_][A-Za-z0-9_]*)=(.*)$`)

// sessionCredentials are short-lived AWS credentials.
type sessionCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Region          string
}

func (c sessionCredentials) valid() bool {
	return c.AccessKeyID != "" && c.SecretAccessKey != ""
}

func credentialsFromEnv(region string) (sessionCredentials, bool) {
	accessKey := os.Getenv("AWS_ACCESS_KEY_ID")
	secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	if accessKey == "" || secretKey == "" {
		return sessionCredentials{}, false
	}

	envRegion := os.Getenv("AWS_REGION")
	if envRegion == "" {
		envRegion = os.Getenv("AWS_DEFAULT_REGION")
	}
	if envRegion == "" {
		envRegion = region
	}

	return sessionCredentials{
		AccessKeyID:     accessKey,
		SecretAccessKey: secretKey,
		SessionToken:    os.Getenv("AWS_SESSION_TOKEN"),
		Region:          envRegion,
	}, true
}

func credentialsFromAwsume(ctx context.Context, profile, roleARN, region string) (sessionCredentials, error) {
	bin, err := findAwsumeBinary()
	if err != nil {
		return sessionCredentials{}, err
	}

	args := awsumeArgs(profile, roleARN, region)
	cmd := exec.CommandContext(ctx, bin, args...)
	var stdout bytes.Buffer
	cmd.Stdin = os.Stdin
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr

	runErr := cmd.Run()

	creds, parseErr := parseAwsumeOutput(stdout.String(), region)
	if parseErr == nil && creds.valid() {
		return creds, nil
	}

	if runErr != nil {
		return sessionCredentials{}, fmt.Errorf("awsume %s failed: %w", strings.Join(args, " "), runErr)
	}
	if parseErr != nil {
		return sessionCredentials{}, fmt.Errorf("parse awsume output: %w", parseErr)
	}
	return sessionCredentials{}, fmt.Errorf("awsume did not return AWS credentials")
}

func awsumeArgs(profile, roleARN, region string) []string {
	if roleARN != "" {
		return []string{
			"--role-arn", roleARN,
			"--source-profile", profile,
			"-s",
			"--region", region,
		}
	}
	return []string{profile, "-s", "--region", region}
}

func findAwsumeBinary() (string, error) {
	if path, err := exec.LookPath("awsumepy"); err == nil {
		return path, nil
	}
	if path, err := exec.LookPath("awsume"); err == nil {
		return path, nil
	}
	return "", fmt.Errorf("awsume/awsumepy not found on PATH")
}

func parseAwsumeOutput(output, defaultRegion string) (sessionCredentials, error) {
	if creds, err := parseAwsumeExports(output); err == nil && creds.AccessKeyID != "" {
		if creds.Region == "" {
			creds.Region = defaultRegion
		}
		return creds, nil
	}
	return parseAwsumeInline(output, defaultRegion)
}

func parseAwsumeInline(output, defaultRegion string) (sessionCredentials, error) {
	for line := range strings.SplitSeq(strings.TrimSpace(output), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Awsume ") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 5 {
			return sessionCredentials{}, fmt.Errorf("unexpected awsume inline output")
		}

		region := fields[4]
		if region == "" {
			region = defaultRegion
		}

		return sessionCredentials{
			AccessKeyID:     fields[1],
			SecretAccessKey: fields[2],
			SessionToken:    fields[3],
			Region:          region,
		}, nil
	}

	return sessionCredentials{}, fmt.Errorf("no awsume credentials found in output")
}

func parseAwsumeExports(output string) (sessionCredentials, error) {
	var creds sessionCredentials

	for line := range strings.SplitSeq(strings.TrimSpace(output), "\n") {
		line = strings.TrimSpace(line)
		matches := exportLine.FindStringSubmatch(line)
		if len(matches) != 3 {
			continue
		}

		key := matches[1]
		value := strings.Trim(matches[2], `"'`)

		switch key {
		case "AWS_ACCESS_KEY_ID":
			creds.AccessKeyID = value
		case "AWS_SECRET_ACCESS_KEY":
			creds.SecretAccessKey = value
		case "AWS_SESSION_TOKEN":
			creds.SessionToken = value
		case "AWS_REGION", "AWS_DEFAULT_REGION":
			if creds.Region == "" {
				creds.Region = value
			}
		}
	}

	return creds, nil
}

func accountFromRoleARN(roleARN string) string {
	parts := strings.Split(roleARN, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}

// AwsumeArgsForTest exposes awsume CLI args for unit tests.
func AwsumeArgsForTest(profile, roleARN, region string) []string {
	return awsumeArgs(profile, roleARN, region)
}

// AccountFromRoleARNForTest exposes account parsing for unit tests.
func AccountFromRoleARNForTest(roleARN string) string {
	return accountFromRoleARN(roleARN)
}
