package archive

import (
	"archive/tar"
	"bytes"
	// "compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// addToArchive adds an opened file to the tar archive
func addToArchive(basepath string, filename string, tw *tar.Writer) error {
	if !filepath.IsAbs(basepath) {
		return fmt.Errorf("basepath %s is not absolute", basepath)
	}
	pathToFile := filepath.Join(basepath, filename)
	file, err := os.Open(pathToFile)
	if err != nil {
		return err
	}
	defer file.Close()
	// get the file info
	info, err := file.Stat()
	if err != nil {
		return err
	}

	// Create a tar Header from the FileInfo data
	header, err := tar.FileInfoHeader(info, info.Name())
	if err != nil {
		return err
	}
	header.Name = filename

	err = tw.WriteHeader(header)
	if err != nil {
		return err
	}

	_, err = io.Copy(tw, file)
	if err != nil {
		return err
	}

	return nil
}

func createArchive(basepath string, files []string, buf io.Writer) error {
	// Create new Writers for gzip and tar
	// These writers are chained. Writing to the tar writer will
	// write to the gzip writer which in turn will write to
	// the "buf" writer
	// gw := gzip.NewWriter(buf)
	// defer gw.Close()
	tw := tar.NewWriter(buf)
	defer tw.Close()

	// Iterate over files and add them to the tar archive
	for _, file := range files {
		err := addToArchive(basepath, file, tw)
		if err != nil {
			return err
		}
	}
	return nil
}

func listFilesInDir(dirname string) ([]string, error) {
	var files []string
	walkFunc := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			files = append(files, path)
		}
		return nil
	}
	err := filepath.Walk(dirname, walkFunc)
	if err != nil {
		return nil, err
	}
	return files, nil
}

func GetArchiveBytes(dirname string) ([]byte, error) {
	var files []string
	// if dirname is a file then just add it to the archive
	fi, err := os.Stat(dirname)
	if err != nil {
		return nil, err
	}
	basepath, err := filepath.Abs(dirname)
	if err != nil {
		return nil, err
	}
	basepath = filepath.Dir(basepath)
	if !fi.IsDir() {
		absFile, err := filepath.Abs(dirname)
		if err != nil {
			return nil, err
		}
		relFile, err := filepath.Rel(basepath, absFile)
		if err != nil {
			return nil, err
		}
		files = append(files, relFile)
		if err != nil {
			return nil, err
		}
	} else {
		filesInDir, err := listFilesInDir(dirname)
		if err != nil {
			return nil, err
		}
		for _, file := range filesInDir {
			absFile, err := filepath.Abs(file)
			if err != nil {
				return nil, err
			}
			relFile, err := filepath.Rel(basepath, absFile)
			if err != nil {
				return nil, err
			}
			files = append(files, relFile)
		}
	}
	if err != nil {
		return nil, err
	}
	// Create a buffer to write our archive to.
	// This buffer is what is returned to the caller
	buf := new(bytes.Buffer)
	err = createArchive(basepath, files, buf)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func Unarchive(basepath string, archive []byte) error {
	// Create a new tar reader
	tr := tar.NewReader(bytes.NewReader(archive))
	// Iterate through the files in the archive.
	for {
		header, err := tr.Next()
		if err == io.EOF {
			// end of tar archive
			break
		}
		if err != nil {
			return err
		}
		// the target location where the dir/file should be created
		target := filepath.Join(basepath, header.Name)
		switch header.Typeflag {
		case tar.TypeDir:
			// handle directory
			// get header permissions
			perm := os.FileMode(header.Mode)
			if err := os.MkdirAll(target, perm); err != nil {
				return err
			}
		case tar.TypeReg:
			// handle normal file
			// create all directories leading to file
			dir := filepath.Dir(target)
			if err := os.MkdirAll(dir, 0755); err != nil {
				return err
			}
			f, err := os.Create(target)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				return err
			}
			f.Close()
			os.Chmod(target, os.FileMode(header.Mode))
		default:
			return fmt.Errorf("unable to untar type: %c in file %s", header.Typeflag, header.Name)
		}
	}
	return nil
}
