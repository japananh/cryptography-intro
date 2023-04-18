package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

// generateAESKey generates an AES key, either 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256.
func generateAESKey(size int) ([]byte, error) {
	if size != 16 && size != 24 && size != 32 {
		return nil, fmt.Errorf("AES key size must be 16, 24 or 32 bytes")
	}
	key := make([]byte, size)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// GenerateIV generates an IV (Initialization Vector). IV must match the block size of cipher used.
func generateIV(size int) ([]byte, error) {
	iv := make([]byte, size)
	_, err := rand.Read(iv)
	if err != nil {
		return nil, err
	}
	return iv, nil
}

// pkcs7Pad adds padding to the end of message to make its length a multiple of 16.
func pkcs7Pad(input []byte) []byte {
	paddingSize := aes.BlockSize - len(input)%aes.BlockSize
	padding := bytes.Repeat([]byte{byte(paddingSize)}, paddingSize)
	return append(input, padding...)
}

// pkcs7UnPad removes padding from the decrypted data to obtain the original plaintext.
// References: https://en.wikipedia.org/wiki/PKCS_7
func pkcs7Unpad(input []byte) ([]byte, error) {
	msgLength := len(input)
	paddingSize := int(input[msgLength-1])

	if paddingSize > msgLength || paddingSize == 0 {
		return nil, fmt.Errorf("invalid padding")
	}

	for i := msgLength - 1; i <= msgLength-paddingSize; i++ {
		if input[i] != byte(paddingSize) {
			return nil, fmt.Errorf("invalid padding")
		}
	}

	return input[:msgLength-paddingSize], nil
}

func encrypt(key, iv, plaintext []byte) ([]byte, error) {
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	copy(ciphertext[:aes.BlockSize], iv)

	stream := cipher.NewCBCEncrypter(blockCipher, iv)
	stream.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

func decrypt(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	decryptedText := make([]byte, len(ciphertext))

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(decryptedText, ciphertext)

	return pkcs7Unpad(decryptedText[aes.BlockSize:])
}

func main() {
	// Generate an AES key, either 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256
	key, err := generateAESKey(16)
	if err != nil {
		panic(err)
	}

	// The Initialization Vector (IV) must be the same size as the block size of the cipher being used.
	// In this example, AES block size = 16 bytes = 128 bits
	iv, err := generateIV(aes.BlockSize)
	if err != nil {
		panic(err)
	}

	// The message you want to encrypt.
	plaintext := []byte("This is a sample message to be encrypted using CBC mode with padding.")

	// Add padding to the message.
	padded := pkcs7Pad(plaintext)

	// Encrypt the message.
	ciphertext, err := encrypt(key, iv, padded)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Encrypted message: %x\n", ciphertext)

	// Decrypt the message.
	decryptedMsg, err := decrypt(key, iv, ciphertext)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Original message: %s\n", plaintext)
	fmt.Printf("Decrypted message: %s\n", decryptedMsg)
}
