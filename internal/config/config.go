package config

// RunConfig holds runtime configuration for plan and apply commands.
type RunConfig struct {
	AccountID   string
	Region      string
	Profile     string
	RoleARN     string
	InputPath   string
	InputEnv    string
	InputB64    bool
	SOPS        bool
	Prune       bool
	AutoApprove bool
	NoColor     bool
}
