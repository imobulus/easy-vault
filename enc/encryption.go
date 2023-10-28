package enc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
)

func addPadding(message []byte, blockSize byte) ([]byte, error) {
	messageLen := len(message)
	blockRemainder := messageLen % int(blockSize)
	if blockRemainder > 255 {
		return nil, errors.New("block size too large")
	}
	paddingLen := blockSize - byte(blockRemainder)
	paddedMessage := make([]byte, messageLen+int(paddingLen))
	// copy message into paddedMessage
	copy(paddedMessage, message)
	// add padding
	for i := 0; i < int(paddingLen); i++ {
		paddedMessage[messageLen+i] = byte(paddingLen)
	}
	return paddedMessage, nil
}

func removePadding(message []byte, blockSize byte) ([]byte, error) {
	messageLen := len(message)
	if messageLen == 0 {
		return nil, errors.New("empty message")
	}
	paddingLen := message[messageLen-1]
	if paddingLen > blockSize {
		return nil, errors.New("invalid padding, larger than block size")
	}
	// check that all last paddingLen bytes are equal to paddingLen
	for i := 0; i < int(paddingLen); i++ {
		if message[messageLen-1-i] != paddingLen {
			return nil, errors.New("invalid padding, not all padding bytes are equal to padding length")
		}
	}
	unpaddedMessage := make([]byte, messageLen-int(paddingLen))
	// copy message into unpaddedMessage
	copy(unpaddedMessage, message)
	return unpaddedMessage, nil
}

func getRandomIV() ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	_, err := io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil, err
	}
	return iv, nil
}

func Encrypt(message []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	paddedMessage, err := addPadding(message, byte(blockSize))
	if err != nil {
		return nil, err
	}
	iv, err := getRandomIV()
	if err != nil {
		return nil, err
	}
	cipherText := make([]byte, len(iv)+len(paddedMessage))
	copy(cipherText, iv)
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[len(iv):], paddedMessage)
	return cipherText, nil
}

func Decrypt(cipherText []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	if len(cipherText) < blockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := cipherText[:blockSize]
	cipherText = cipherText[blockSize:]
	if len(cipherText)%blockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	decryptedMessage := make([]byte, len(cipherText))
	mode.CryptBlocks(decryptedMessage, cipherText)
	if blockSize > 255 {
		return nil, errors.New("block size too large")
	}
	unpaddedMessage, err := removePadding(decryptedMessage, byte(blockSize))
	if err != nil {
		return nil, err
	}
	return unpaddedMessage, nil
}

func GetRandomOrgKey(keysize int) ([]byte, error) {
	url := fmt.Sprintf("https://www.random.org/cgi-bin/randbyte?nbytes=%d", keysize)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func GetSystemRandomKey(keysize int) ([]byte, error) {
	key := make([]byte, keysize)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func ArchiveKeyName(archive []byte) string {
	hash := sha256.Sum256(archive)
	return hex.EncodeToString(hash[:]) + ".key"
}
