package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

// generateAESKey generates an AES key, either 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256
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

// generateIV generates an IV (Initialization Vector). IV must match the block size of cipher used.
func generateIV(size int) ([]byte, error) {
	iv := make([]byte, size)
	_, err := rand.Read(iv)
	if err != nil {
		return nil, err
	}
	return iv, nil
}

// encrypt encrypts plaintext to ciphertext using CFB mode
func encrypt(plaintext []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)

	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)

	return ciphertext, nil
}

// decrypt decrypts ciphertext to plaintext using CFB mode
func decrypt(ciphertext []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	stream := cipher.NewCFBDecrypter(block, iv)

	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

func main() {
	// No need padding to plaintext in CFB
	plaintext := []byte("This is a sample plaintext message to be encrypted in CFB mode.")

	// Generate AES key
	key, err := generateAESKey(16)
	if err != nil {
		panic(err)
	}

	// Initialization Vector (IV) must match the block size of cipher used
	iv, err := generateIV(aes.BlockSize)
	if err != nil {
		panic(err)
	}

	// Encrypt plaintext
	ciphertext, err := encrypt(plaintext, key, iv)
	if err != nil {
		panic(err)
	}

	// Decrypt ciphertext
	decryptedMsg, err := decrypt(ciphertext, key, iv)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Plaintext: %s\n", plaintext)
	fmt.Printf("Ciphertext: %x\n", ciphertext)
	fmt.Printf("Decrypted message: %s\n", decryptedMsg)
}
