package cleardir

import (
	"fmt"
	"os"
	"path/filepath"
)

func WipeFile(path string) error {
	file, err := os.OpenFile(path, os.O_RDWR, 0666)
	if err != nil {
		return err
	}
	defer file.Close()
	fileInfo, err := file.Stat()
	if err != nil {
		return err
	}
	if fileInfo.IsDir() {
		return fmt.Errorf("path is a directory")
	}
	var size int64 = fileInfo.Size()
	zeroBytes := make([]byte, size)
	copy(zeroBytes[:], "0")
	_, err = file.Write(zeroBytes)
	if err != nil {
		return err
	}
	return nil
}

func WipeDir(path string) error {
	walkFunc := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		return WipeFile(path)
	}
	return filepath.Walk(path, walkFunc)
}
