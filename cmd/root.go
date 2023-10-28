package cmd

import (
	"log"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "vault",
	Short: "A simple CLI tool for encrypting and decrypting files",
	Long:  `A simple CLI tool for encrypting and decrypting files`,
}

func Execute() {
	errLogger := log.New(os.Stderr, "", 0)
	if err := rootCmd.Execute(); err != nil {
		errLogger.Println(err)
		os.Exit(1)
	}
}

func init() {
	initEncrypt()
	initDecrypt()
	initInitusb()
	initWipedir()
}
