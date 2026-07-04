package cli

import (
	"fmt"
	"runtime/debug"
	"strings"

	"github.com/spf13/cobra"
)

// Version is the current release version for the CLI.
var Version = "0.1.0-dev"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, _ []string) {
		fmt.Fprintln(cmd.OutOrStdout(), resolveVersion())
	},
}

func resolveVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		if info.Main.Version != "" && info.Main.Version != "(devel)" {
			return strings.TrimSpace(info.Main.Version)
		}
	}
	if strings.TrimSpace(Version) != "" {
		return strings.TrimSpace(Version)
	}
	return "0.0.0-unknown"
}
