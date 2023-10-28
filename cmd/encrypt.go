package cmd

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/spf13/cobra"
	"imobul.us/vault/archive"
	"imobul.us/vault/cleardir"
	"imobul.us/vault/constants"
	"imobul.us/vault/enc"

	usb "github.com/deepakjois/gousbdrivedetector"
)

type EncryptApp struct {
	cmd                *cobra.Command
	args               []string
	keysize            int
	absoluteOutputPath string
	keyDir             string
	key                []byte
}

func (app *EncryptApp) reportError(err string) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func (app *EncryptApp) confirmAction(prompt string) bool {
	fmt.Fprintf(os.Stderr, "%s [y/n] ", prompt)
	var response string
	fmt.Scanln(&response)
	return response == "y"
}

func validateEncryptArgs(cmd *cobra.Command, args []string) error {
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

func (app *EncryptApp) getAbsoluteOutputPath() string {
	if app.absoluteOutputPath != "" {
		return app.absoluteOutputPath
	}
	if app.cmd.Flag("output").Changed {
		filename, err := app.cmd.Flags().GetString("output")
		if err != nil {
			panic(err)
		}
		// if file exists throw error
		if _, err := os.Stat(filename); err == nil {
			app.reportError(fmt.Sprintf("file %s already exists", filename))
		}
		absFilename, err := filepath.Abs(filename)
		if err != nil {
			app.reportError(fmt.Sprintf("unable to determine absolute path for %s", filename))
		}
		app.absoluteOutputPath = absFilename
		return absFilename
	}
	pathToEncrypt := app.args[0]
	fullPathToEncrypt, err := filepath.Abs(pathToEncrypt)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	dirName, fileName := filepath.Split(fullPathToEncrypt)
	if fileName == "" {
		app.reportError("unable to determine output file, are you trying to encrypt root directory?")
	}
	encryptedFileName := filepath.Join(dirName, fileName+".enc")
	// if exists, exit
	if _, err := os.Stat(encryptedFileName); err == nil {
		app.reportError(fmt.Sprintf("file %s already exists", encryptedFileName))
	}
	app.absoluteOutputPath = encryptedFileName
	return encryptedFileName
}

func getApplicableUsbKeyDirs() ([]string, error) {
	usbDevices, err := usb.Detect()
	if err != nil {
		return nil, err
	}
	if len(usbDevices) == 0 {
		return nil, fmt.Errorf("no USB drives found")
	}
	var applicableKeyDirs []string
	for _, usbDevice := range usbDevices {
		keyDir := filepath.Join(usbDevice, constants.KeysDir)
		if info, err := os.Stat(keyDir); err == nil && info.IsDir() {
			applicableKeyDirs = append(applicableKeyDirs, keyDir)
		}
	}
	if len(applicableKeyDirs) == 0 {
		return nil, fmt.Errorf("no applicable key directories found, please use initusb command to initialize usb drive")
	}
	return applicableKeyDirs, nil
}

func (app *EncryptApp) promptKeyDir(keyDirs []string) string {
	fmt.Fprintln(os.Stderr, "Multiple key directories found. Please select one:")
	for i, keyDir := range keyDirs {
		fmt.Fprintf(os.Stderr, "%d: %s\n", i+1, keyDir)
	}
	var response string
	fmt.Fprint(os.Stderr, "Choose a drive or type abort: ")
	for {
		fmt.Scanln(&response)
		if response == "abort" {
			os.Exit(1)
		}
		index, err := strconv.Atoi(response)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Invalid input. Please try again")
			continue
		}
		if index < 1 || index > len(keyDirs) {
			fmt.Fprintln(os.Stderr, "Invalid input. Please try again")
			continue
		}
		return keyDirs[index-1]
	}
}

func (app *EncryptApp) getUsbKeyDir() string {
	applicableKeyDirs, err := getApplicableUsbKeyDirs()
	if err != nil {
		app.reportError(err.Error())
	}
	if len(applicableKeyDirs) == 1 {
		return applicableKeyDirs[0]
	}
	return app.promptKeyDir(applicableKeyDirs)
}

func (app *EncryptApp) getKeyDir() string {
	if app.keyDir != "" {
		return app.keyDir
	}
	keyDir, err := app.cmd.Flags().GetString("keydir")
	if err != nil {
		panic(err)
	}
	if keyDir != "" {
		// check if keydir exists
		if finfo, err := os.Stat(keyDir); err != nil || !finfo.IsDir() {
			app.reportError(fmt.Sprintf("keydir %s does not exist", keyDir))
		}
		return keyDir
	}
	// if usb flag is set use usb keydir
	if app.cmd.Flag("usb").Changed {
		usbKeyDir := app.getUsbKeyDir()
		app.keyDir = usbKeyDir
		return usbKeyDir
	}
	// else use output directory
	fmt.Fprintln(os.Stderr, "no key directory specified, using output directory")
	outputFile := app.getAbsoluteOutputPath()
	dirName, _ := filepath.Split(outputFile)
	app.keyDir = dirName
	return dirName
}

func (app *EncryptApp) getKey() []byte {
	if len(app.key) != 0 {
		return app.key
	}
	systemKey, err := enc.GetSystemRandomKey(app.keysize)
	if err != nil {
		randorgOnly := app.confirmAction("unable to generate random key, do you want to continue with key from random.org only?")
		if !randorgOnly {
			app.reportError("aborting")
		}
		systemKey = make([]byte, app.keysize)
		for i := range systemKey {
			systemKey[i] = 0
		}
	}
	randOrgKey, err := enc.GetRandomOrgKey(app.keysize)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		noRandorg := app.confirmAction("unable to get key from random.org, do you want to proceed without it?")
		if !noRandorg {
			app.reportError("aborting")
		}
		randOrgKey = make([]byte, app.keysize)
		for i := range randOrgKey {
			randOrgKey[i] = 0
		}
	}
	newKey := make([]byte, app.keysize)
	for i := range newKey {
		newKey[i] = systemKey[i] + randOrgKey[i]
	}
	// if newKey is filled with zeros - abort
	allZeros := true
	for i := range newKey {
		if newKey[i] != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		app.reportError("unable to generate key")
	}
	app.key = newKey
	return newKey
}

func writeKey(keyPath string, key []byte) error {
	// if keyPath already exists, exit
	if _, err := os.Stat(keyPath); err == nil {
		return fmt.Errorf("key file %s already exists, that's near impossible", keyPath)
	}
	file, err := os.Create(keyPath)
	if err != nil {
		return err
	}
	defer file.Close()
	keyHex := hex.EncodeToString(key)
	_, err = file.WriteString(keyHex)
	if err != nil {
		return err
	}
	return nil
}

func writeArchive(archivePath string, archiveBytes []byte) error {
	file, err := os.Create(archivePath)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(archiveBytes)
	if err != nil {
		return err
	}
	return nil
}

func (app *EncryptApp) run() {
	// get keydir
	keyDir := app.getKeyDir()
	// get absolute output path
	absoluteOutputPath := app.getAbsoluteOutputPath()
	// get key
	key := app.getKey()
	// get archive bytes
	archiveBytes, err := archive.GetArchiveBytes(app.args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "could not archive directory contents:")
		app.reportError(err.Error())
	}
	// encrypt file
	encryptedArchive, err := enc.Encrypt(archiveBytes, key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "could not encrypt directory contents:")
		app.reportError(err.Error())
	}
	keyFileName := enc.ArchiveKeyName(encryptedArchive)
	// write key to file
	keyPath := filepath.Join(keyDir, keyFileName)
	err = writeKey(keyPath, key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "could not write key file:")
		app.reportError(err.Error())
	}
	fmt.Fprintln(os.Stderr, "key written to", keyPath)
	// write encrypted file
	err = writeArchive(absoluteOutputPath, encryptedArchive)
	if err != nil {
		fmt.Fprintln(os.Stderr, "could not write encrypted content:")
		app.reportError(err.Error())
	}
	fmt.Fprintln(os.Stderr, "encrypted data written to", absoluteOutputPath)
	keep, err := app.cmd.Flags().GetBool("keep")
	if err != nil {
		panic(err)
	}
	if !keep {
		// wipe the original directory
		err = cleardir.WipeDir(app.args[0])
		if err != nil {
			fmt.Fprintln(os.Stderr, "could not wipe original directory:")
			app.reportError(err.Error())
		}
		// remove original directory
		err = os.RemoveAll(app.args[0])
		if err != nil {
			fmt.Fprintln(os.Stderr, "could not remove original directory:")
			app.reportError(err.Error())
		}
	}
}

func executeEncrypt(cmd *cobra.Command, args []string) {
	app := EncryptApp{
		cmd:     cmd,
		args:    args,
		keysize: 32,
	}
	app.run()
}

var encryptCmd = &cobra.Command{
	Use:   "encrypt <filename>",
	Short: "encrypt files",
	Long:  `encrypt files`,
	Run:   executeEncrypt,
	Args:  validateEncryptArgs,
}

func initEncrypt() {
	encryptCmd.Flags().StringP("key", "k", "", "key to use for encryption")
	encryptCmd.Flags().String("keydir", "", "directory to store the key")
	encryptCmd.Flags().StringP("output", "o", "", "output file")
	encryptCmd.Flags().Bool("keep", false, "keep original file after encryption")
	encryptCmd.Flags().Bool("usb", false, "automatically scan for usb drives to store the key")
	rootCmd.AddCommand(encryptCmd)
}
