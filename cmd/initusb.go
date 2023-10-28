package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	usb "github.com/deepakjois/gousbdrivedetector"
	"github.com/spf13/cobra"
	"imobul.us/vault/constants"
)

type InitusbApp struct {
	cmd  *cobra.Command
	args []string
}

func (app *InitusbApp) reportError(err string) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func (app *InitusbApp) promptUsbDevice() string {
	usbDevices, err := usb.Detect()
	if err != nil {
		fmt.Fprintln(os.Stderr, "could not detect usb devices:")
		app.reportError(err.Error())
	}
	if len(usbDevices) == 0 {
		app.reportError("no usb devices found")
	}
	if len(usbDevices) == 1 {
		return usbDevices[0]
	}
	for i, usbDevice := range usbDevices {
		fmt.Fprintf(os.Stderr, "%d: %s\n", i+1, usbDevice)
	}
	for {
		fmt.Fprintf(os.Stderr, "select a USB device or enter abort: ")
		var response string
		fmt.Scanln(&response)
		if response == "abort" {
			os.Exit(1)
		}
		deviceId, err := strconv.Atoi(response)
		if err != nil {
			fmt.Fprintln(os.Stderr, "invalid response")
			continue
		}
		if deviceId < 1 || deviceId > len(usbDevices) {
			fmt.Fprintln(os.Stderr, "invalid response")
			continue
		}
		return usbDevices[deviceId-1]
	}
}

func (app *InitusbApp) initUsbDevice(usbDevice string) {
	// if KeyDir exists, report it and exit
	keysDir := filepath.Join(usbDevice, constants.KeysDir)
	if info, err := os.Stat(keysDir); err == nil && info.IsDir() {
		fmt.Fprintf(os.Stderr, "device %s is already initialized\n", usbDevice)
		os.Exit(0)
	}
	// create KeyDir
	if err := os.Mkdir(keysDir, 0700); err != nil {
		app.reportError(err.Error())
	}
	fmt.Fprintf(os.Stderr, "device %s initialized\n", usbDevice)
}

func (app *InitusbApp) run() {
	usbDevice := app.promptUsbDevice()
	app.initUsbDevice(usbDevice)
}

func executeInitusb(cmd *cobra.Command, args []string) {
	app := InitusbApp{cmd, args}
	app.run()
}

var initusbCmd = &cobra.Command{
	Use:   "initusb",
	Short: "Initialize a USB drive for use with vault",
	Long:  `Initialize a USB drive for use with vault`,
	Run:   executeInitusb,
}

func initInitusb() {
	rootCmd.AddCommand(initusbCmd)
}
