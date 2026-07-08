package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/spf13/cobra"

	"github.com/jkarkoszka/secrets-syncer/internal/auth"
	"github.com/jkarkoszka/secrets-syncer/internal/config"
	"github.com/jkarkoszka/secrets-syncer/internal/input"
	"github.com/jkarkoszka/secrets-syncer/internal/output"
	"github.com/jkarkoszka/secrets-syncer/internal/planner"
	"github.com/jkarkoszka/secrets-syncer/internal/provider"
	"github.com/jkarkoszka/secrets-syncer/internal/provider/awssecretsmanager"
	"github.com/jkarkoszka/secrets-syncer/internal/sops"
)

var (
	runConfig config.RunConfig

	providerFactory providerFactoryFunc = defaultProviderFactory
	decryptor       sops.Decryptor      = sops.NewCLIDecryptor()
	stdinReader     io.Reader           = os.Stdin
	openTTY                             = os.Open
)

type providerFactoryFunc func(context.Context, config.RunConfig) (provider.SecretProvider, *auth.Identity, error)

// Execute runs the CLI.
func Execute() error {
	return rootCmd.Execute()
}

var rootCmd = &cobra.Command{
	Use:           "secrets-syncer",
	Short:         "GitOps-style secret management for AWS Secrets Manager",
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRun: func(_ *cobra.Command, _ []string) {
		output.SetNoColor(runConfig.NoColor)
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&runConfig.InputPath, "input", "", "input file path or - for stdin")
	rootCmd.PersistentFlags().StringVar(&runConfig.InputEnv, "input-env", "", "read input from environment variable")
	rootCmd.PersistentFlags().BoolVar(&runConfig.SOPS, "sops", false, "decrypt SOPS-encrypted input during execution")
	rootCmd.PersistentFlags().BoolVar(&runConfig.NoColor, "no-color", false, "disable colored output")

	rootCmd.AddCommand(validateCmd)
	rootCmd.AddCommand(planCmd)
	rootCmd.AddCommand(applyCmd)
	rootCmd.AddCommand(versionCmd)

	addAWSFlags(planCmd)
	addAWSFlags(applyCmd)
	planCmd.Flags().BoolVar(&runConfig.Prune, "prune", false, "include deletion of managed secrets not in input")

	applyCmd.Flags().BoolVar(&runConfig.Prune, "prune", false, "delete managed secrets not in input")
	applyCmd.Flags().BoolVar(&runConfig.AutoApprove, "auto-approve", false, "apply without interactive confirmation")
}

func addAWSFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&runConfig.AccountID, "account-id", "", "expected AWS account ID")
	cmd.Flags().StringVar(&runConfig.Region, "region", "", "AWS region")
	cmd.Flags().StringVar(&runConfig.Profile, "profile", "", "AWS shared config profile")
	cmd.Flags().StringVar(&runConfig.RoleARN, "role-arn", "", "IAM role ARN to assume")
}

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate input configuration",
	RunE: func(cmd *cobra.Command, _ []string) error {
		doc, err := loadDocument(cmd.Context())
		if err != nil {
			return err
		}
		if err := validateInput(doc, false); err != nil {
			return err
		}
		output.NewFormatter().WriteValidateSuccess()
		return nil
	},
}

var planCmd = &cobra.Command{
	Use:   "plan",
	Short: "Show planned secret changes",
	RunE: func(cmd *cobra.Command, _ []string) error {
		doc, err := loadDocument(cmd.Context())
		if err != nil {
			return err
		}
		if err := validateAWSFlags(doc.Provider); err != nil {
			return err
		}

		prov, identity, err := providerFactory(cmd.Context(), runConfig)
		if err != nil {
			return err
		}

		plan, err := buildPlan(cmd.Context(), doc, prov)
		if err != nil {
			return err
		}

		scope := buildScope(doc.Provider, identity)
		if err := output.NewFormatter().WritePlan(plan, scope); err != nil {
			return err
		}
		if plan.HasConflicts() {
			return fmt.Errorf("plan contains unmanaged secret conflicts")
		}
		return nil
	},
}

var applyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Apply secret changes",
	RunE: func(cmd *cobra.Command, _ []string) error {
		doc, err := loadDocument(cmd.Context())
		if err != nil {
			return err
		}
		if err := validateAWSFlags(doc.Provider); err != nil {
			return err
		}

		prov, identity, err := providerFactory(cmd.Context(), runConfig)
		if err != nil {
			return err
		}

		plan, err := buildPlan(cmd.Context(), doc, prov)
		if err != nil {
			return err
		}

		formatter := output.NewFormatter()
		scope := buildScope(doc.Provider, identity)
		if err := formatter.WritePlan(plan, scope); err != nil {
			return err
		}
		if plan.HasConflicts() {
			return fmt.Errorf("apply blocked due to unmanaged secret conflicts")
		}
		if !plan.HasChanges() {
			return nil
		}
		if !runConfig.AutoApprove {
			reader, cleanup, err := confirmationReader()
			if err != nil {
				return err
			}
			defer cleanup()

			approved, err := confirmApply(reader)
			if err != nil {
				return err
			}
			if !approved {
				return fmt.Errorf("apply cancelled")
			}
		}

		stats, err := planner.Apply(cmd.Context(), prov, plan)
		if err != nil {
			return err
		}
		formatter.WriteApplyComplete(stats)
		return nil
	},
}

func validateAWSFlags(providerName string) error {
	if providerName != provider.ProviderAWS {
		return fmt.Errorf("unsupported provider %q", providerName)
	}
	return nil
}

func loadDocument(ctx context.Context) (*input.Document, error) {
	pathHint, data, err := readInputBytes(ctx)
	if err != nil {
		return nil, err
	}

	doc, err := input.Parse(data, pathHint)
	if err != nil {
		return nil, err
	}
	return doc, nil
}

func readInputBytes(ctx context.Context) (string, []byte, error) {
	if runConfig.InputEnv != "" {
		if runConfig.SOPS {
			return "", nil, fmt.Errorf("--sops is not supported with --input-env")
		}
		value := os.Getenv(runConfig.InputEnv)
		if value == "" {
			return "", nil, fmt.Errorf("input environment variable %s is empty", runConfig.InputEnv)
		}
		return "env", []byte(value), nil
	}

	if runConfig.InputPath == "" {
		return "", nil, fmt.Errorf("input is required")
	}

	if runConfig.InputPath == "-" {
		data, err := io.ReadAll(stdinReader)
		if err != nil {
			return "", nil, fmt.Errorf("read stdin: %w", err)
		}
		if runConfig.SOPS {
			data, err = decryptor.Decrypt(ctx, "-", data)
			if err != nil {
				return "", nil, err
			}
		}
		return "-", data, nil
	}

	if runConfig.SOPS {
		data, err := decryptor.Decrypt(ctx, runConfig.InputPath, nil)
		return runConfig.InputPath, data, err
	}
	data, err := input.ReadBytes(runConfig.InputPath)
	return runConfig.InputPath, data, err
}

func buildPlan(ctx context.Context, doc *input.Document, prov provider.SecretProvider) (*planner.Plan, error) {
	if err := validateInput(doc, runConfig.Prune); err != nil {
		return nil, err
	}

	desired := input.ToDesired(doc)
	return planner.Generate(ctx, prov, desired, planner.Options{Prune: runConfig.Prune})
}

func validateInput(doc *input.Document, allowEmpty bool) error {
	if err := input.Validate(doc); err != nil {
		return err
	}
	if !allowEmpty && len(doc.Secrets) == 0 {
		return fmt.Errorf("input must contain at least one secret (or use --prune to delete managed secrets)")
	}
	return nil
}

func defaultProviderFactory(ctx context.Context, cfg config.RunConfig) (provider.SecretProvider, *auth.Identity, error) {
	awsCfg, err := auth.LoadConfig(ctx, auth.Options{
		Region:  cfg.Region,
		Profile: cfg.Profile,
		RoleARN: cfg.RoleARN,
	})
	if err != nil {
		return nil, nil, err
	}
	if err := auth.ValidateAccountID(ctx, awsCfg, cfg.AccountID); err != nil {
		return nil, nil, err
	}
	identity := &auth.Identity{Region: awsCfg.Region}
	if resolved, err := auth.ResolveIdentity(ctx, awsCfg); err == nil {
		identity = &resolved
	}

	sm := secretsmanager.NewFromConfig(awsCfg)
	tags := resourcegroupstaggingapi.NewFromConfig(awsCfg)
	return awssecretsmanager.New(sm, tags), identity, nil
}

func buildScope(providerName string, identity *auth.Identity) output.Scope {
	scope := output.Scope{
		Provider: providerName,
		Profile:  runConfig.Profile,
		RoleARN:  runConfig.RoleARN,
	}
	if identity != nil {
		scope.Region = identity.Region
		scope.AccountID = identity.AccountID
		scope.AccountAlias = identity.AccountAlias
	}
	if scope.AccountID == "" && runConfig.AccountID != "" {
		scope.AccountID = runConfig.AccountID
		scope.AccountNote = "expected"
	}
	if scope.Region == "" {
		scope.Region = runConfig.Region
	}
	return scope
}

func confirmationReader() (io.Reader, func(), error) {
	// Stdin is already consumed when --input - is used; prompt on the terminal instead.
	if runConfig.InputPath != "-" {
		return stdinReader, func() {}, nil
	}

	tty, err := openTTY("/dev/tty")
	if err != nil {
		return nil, nil, fmt.Errorf("cannot prompt for confirmation: stdin was used for input; use --auto-approve or run in a TTY")
	}
	return tty, func() { _ = tty.Close() }, nil
}

func confirmApply(r io.Reader) (bool, error) {
	fmt.Fprintf(os.Stdout, "\nDo you want to perform these actions? Only 'yes' will be accepted to approve.\n\nEnter a value: ")
	scanner := bufio.NewScanner(r)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return false, err
		}
		return false, nil
	}
	return strings.TrimSpace(scanner.Text()) == "yes", nil
}

// SetProviderFactory overrides provider creation for tests.
func SetProviderFactory(factory func(context.Context, config.RunConfig) (provider.SecretProvider, *auth.Identity, error)) {
	providerFactory = factory
}

// ResetProviderFactory restores the default provider factory.
func ResetProviderFactory() {
	providerFactory = defaultProviderFactory
}

// SetDecryptor overrides SOPS decryption for tests.
func SetDecryptor(d sops.Decryptor) {
	decryptor = d
}

// ResetDecryptor restores the default SOPS decryptor.
func ResetDecryptor() {
	decryptor = sops.NewCLIDecryptor()
}

// SetOpenTTY overrides TTY open for tests.
func SetOpenTTY(fn func(string) (*os.File, error)) {
	openTTY = fn
}

// ResetOpenTTY restores default TTY open.
func ResetOpenTTY() {
	openTTY = os.Open
}

// SetStdinReader overrides stdin for tests.
func SetStdinReader(r io.Reader) {
	stdinReader = r
}

// ResetStdinReader restores default stdin.
func ResetStdinReader() {
	stdinReader = os.Stdin
}

// SetRunConfig sets run configuration for tests.
func SetRunConfig(cfg config.RunConfig) {
	runConfig = cfg
}

// RootCommand returns the root cobra command for tests.
func RootCommand() *cobra.Command {
	return rootCmd
}

// GetRunConfig returns the current run configuration.
func GetRunConfig() config.RunConfig {
	return runConfig
}

// ResetRunConfig clears run configuration for tests.
func ResetRunConfig() {
	runConfig = config.RunConfig{}
}
