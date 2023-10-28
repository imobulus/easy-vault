package cmd

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"imobul.us/vault/archive"
	"imobul.us/vault/cleardir"
	"imobul.us/vault/constants"
	"imobul.us/vault/enc"

	usb "github.com/deepakjois/gousbdrivedetector"
)

type DecryptApp struct {
	cmd  *cobra.Command
	args []string
}

func (app *DecryptApp) reportError(err string) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func (app *DecryptApp) getUsbKey(keyFileName string) []byte {
	usbDevices, err := usb.Detect()
	if err != nil {
		fmt.Fprintln(os.Stderr, "could not detect usb devices:")
		app.reportError(err.Error())
	}
	for _, usbDevice := range usbDevices {
		keysDir := filepath.Join(usbDevice, constants.KeysDir)
		// if no directory .vault_key is found, continue
		if info, err := os.Stat(keysDir); os.IsNotExist(err) || !info.IsDir() {
			continue
		}
		// if directory .vault_key is found, check if key file exists
		keyFile := filepath.Join(keysDir, keyFileName)
		if info, err := os.Stat(keyFile); os.IsNotExist(err) || info.IsDir() {
			continue
		}
		// if key file exists, read it
		keyBytes, err := os.ReadFile(keyFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "could not read key file:")
			fmt.Fprintln(os.Stderr, err.Error())
			continue
		}
		// decode key from hex
		decodedKey, err := hex.DecodeString(string(keyBytes))
		if err != nil {
			fmt.Fprintln(os.Stderr, "could not decode key:")
			fmt.Fprintln(os.Stderr, err.Error())
			continue
		}
		return decodedKey
	}
	app.reportError("could not find key file on usb devices")
	return nil
}

func (app *DecryptApp) getKeyFromDir(keyDir string, keyFilename string) []byte {
	// get key bytes from key file
	keyFile, err := os.Open(filepath.Join(keyDir, keyFilename))
	if err != nil {
		fmt.Fprintln(os.Stderr, "could not open key file:")
		app.reportError(err.Error())
	}
	defer keyFile.Close()
	keyHexBytes, err := io.ReadAll(keyFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "could not read key file:")
		app.reportError(err.Error())
	}
	keyBytes, err := hex.DecodeString(string(keyHexBytes))
	if err != nil {
		fmt.Fprintln(os.Stderr, "could not decode key:")
		app.reportError(err.Error())
	}
	return keyBytes
}

func (app *DecryptApp) getKey(encryptedBtyes []byte) []byte {
	// if flag key is set, use it
	keyFlag, err := app.cmd.Flags().GetString("key")
	if err != nil {
		fmt.Fprintln(os.Stderr, "could not get key flag:")
		app.reportError(err.Error())
	}
	if keyFlag != "" {
		// decode key from hex
		keyBytes, err := hex.DecodeString(keyFlag)
		if err != nil {
			fmt.Fprintln(os.Stderr, "could not decode key:")
			app.reportError(err.Error())
		}
		return keyBytes
	}
	keyDir, err := app.cmd.Flags().GetString("keydir")
	if err != nil {
		fmt.Fprintln(os.Stderr, "could not get keydir flag:")
		app.reportError(err.Error())
	}
	// get key filename from encrypted bytes
	keyFilename := enc.ArchiveKeyName(encryptedBtyes)
	// if keydir is set, use it
	if keyDir != "" {
		return app.getKeyFromDir(keyDir, keyFilename)
	}
	usbFlag, err := app.cmd.Flags().GetBool("usb")
	if err != nil {
		fmt.Fprintln(os.Stderr, "could not get usb flag:")
		app.reportError(err.Error())
	}
	if usbFlag {
		return app.getUsbKey(keyFilename)
	}
	// if keydir is not set, report error
	fmt.Fprintln(os.Stderr, "no key finding method specified, using current directory")
	return app.getKeyFromDir(".", keyFilename)
}

func (app *DecryptApp) getOutputDirectory() string {
	// get output directory
	// if flag output is set, use it
	outputFlag, err := app.cmd.Flags().GetString("output")
	if err != nil {
		fmt.Fprintln(os.Stderr, "could not get output flag:")
		app.reportError(err.Error())
	}
	if outputFlag != "" {
		return outputFlag
	}
	// if output is not set, use the directory of the encrypted file
	abspath, err := filepath.Abs(app.args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "could not get absolute path of encrypted file:")
		app.reportError(err.Error())
	}
	return filepath.Dir(abspath)
}

func (app *DecryptApp) run() {
	encryptedFileName := app.args[0]
	// get decrypt file bytes
	fileToDecrypt, err := os.Open(encryptedFileName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "could not open encrypted file:")
		app.reportError(err.Error())
	}
	encryptedArchiveBytes, err := io.ReadAll(fileToDecrypt)
	if err != nil {
		fmt.Fprintln(os.Stderr, "could not read encrypted file:")
		app.reportError(err.Error())
	}
	err = fileToDecrypt.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, "could not close encrypted file:")
		app.reportError(err.Error())
	}
	// get key bytes
	keyBytes := app.getKey(encryptedArchiveBytes)
	// decrypt archive bytes
	decryptedArchiveBytes, err := enc.Decrypt(encryptedArchiveBytes, keyBytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "could not decrypt file:")
		app.reportError(err.Error())
	}
	// get directory to write to
	outputDir := app.getOutputDirectory()
	err = archive.Unarchive(outputDir, decryptedArchiveBytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "could not unarchive file:")
		app.reportError(err.Error())
	}
	err = cleardir.WipeDir(encryptedFileName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "could not wipe encrypted file:")
		app.reportError(err.Error())
	}
	// remove encrypted file
	err = os.Remove(encryptedFileName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "could not remove encrypted file:")
		app.reportError(err.Error())
	}
}

func executeDecrypt(cmd *cobra.Command, args []string) {
	app := DecryptApp{
		cmd:  cmd,
		args: args,
	}
	app.run()
}

func validateDecryptArgs(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("encrypt requires exactly one argument")
	}
	path := args[0]
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return fmt.Errorf("file %s does not exist", path)
	}
	if err != nil {
		return fmt.Errorf("could not open file %s", path)
	}
	defer file.Close()
	return nil
}

var decryptCmd = &cobra.Command{
	Use:   "decrypt <filename>",
	Short: "decrypt previously encrypted files",
	Long:  `decrypt previously encrypted files`,
	Run:   executeDecrypt,
	Args:  validateDecryptArgs,
}

func initDecrypt() {
	decryptCmd.Flags().String("keydir", "", "directory to take the key from")
	decryptCmd.Flags().StringP("key", "k", "", "key in hex format to use for decryption")
	decryptCmd.Flags().StringP("output", "o", "", "output directory")
	decryptCmd.Flags().Bool("usb", false, "scan for keys un usb devices")
	rootCmd.AddCommand(decryptCmd)
}
