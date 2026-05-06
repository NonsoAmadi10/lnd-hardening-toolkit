package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	configPath   string
	lndDir       string
	outputFormat string
	minSeverity  string
	failOn       string
	verbose      bool
	noColor      bool
	quiet        bool
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan an LND node for security issues",
	Long: `Scan an LND node's configuration and runtime state for security
misconfigurations, weak defaults, and hardening opportunities.

Supports two modes:
  - Config-only: reads lnd.conf and the data directory (no running node needed)
  - Live: connects via gRPC for runtime checks (requires a running node)

If no --config flag is provided, the scanner will attempt to auto-detect
the LND configuration at common paths (~/.lnd/lnd.conf).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("⚡ LND Hardening Toolkit")
		fmt.Println("Scanner not yet implemented — coming soon.")
		return nil
	},
}

func init() {
	scanCmd.Flags().StringVar(&configPath, "config", "", "path to lnd.conf (auto-detected if not set)")
	scanCmd.Flags().StringVar(&lndDir, "lnddir", "", "LND data directory (auto-detected if not set)")
	scanCmd.Flags().StringVar(&outputFormat, "format", "table", "output format: table, json, sarif")
	scanCmd.Flags().StringVar(&minSeverity, "min-severity", "low", "minimum severity to display: critical, high, medium, low, info")
	scanCmd.Flags().StringVar(&failOn, "fail-on", "critical", "exit 1 if any finding at or above this severity")
	scanCmd.Flags().BoolVar(&verbose, "verbose", false, "show INFO-level findings")
	scanCmd.Flags().BoolVar(&noColor, "no-color", false, "disable colored output")
	scanCmd.Flags().BoolVar(&quiet, "quiet", false, "only output the score")

	rootCmd.AddCommand(scanCmd)
}
