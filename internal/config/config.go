package config

// RunConfig holds runtime configuration for plan and apply commands.
type RunConfig struct {
	Provider     string
	AccountID    string
	Region       string
	Profile      string
	RoleARN      string
	InputPath    string
	SOPS         bool
	Prune        bool
	AutoApprove  bool
	NoColor      bool
}
