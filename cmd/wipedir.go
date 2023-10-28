package cmd

import (
	"github.com/spf13/cobra"
	"imobul.us/vault/cleardir"
)

func executeWipedir(cmd *cobra.Command, args []string) {
	cleardir.WipeDir(args[0])
}

var wipedirCmd = &cobra.Command{
	Use:   "wipedir",
	Short: "wipe a directory",
	Long:  `wipe a directory`,
	Run:   executeWipedir,
}

func initWipedir() {
	rootCmd.AddCommand(wipedirCmd)
}
