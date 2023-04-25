package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

// generateAESKey generates an AES key, either 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256
func generateAESKey(size int) ([]byte, error) {
	if size == 16 || size == 24 || size == 32 {
		key := make([]byte, size)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		return key, nil
	}

	return nil, fmt.Errorf("AES key size must be 16, 24 or 32 bytes")
}

// encrypt encrypts plaintext to ciphertext using CTR mode
func encrypt(plaintext, key []byte) ([]byte, error) {
	// Create AES encryption block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

// decrypt decrypts ciphertext to plaintext using CTR mode
func decrypt(ciphertext, key []byte) ([]byte, error) {
	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}

func main() {
	plaintext := []byte("Hello World!")

	fmt.Printf("Plaintext: %s\n", plaintext)

	key, err := generateAESKey(16)
	if err != nil {
		panic(err)
	}

	ciphertext, err := encrypt(plaintext, key)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Ciphertext: %x\n", ciphertext)

	decrypted, err := decrypt(ciphertext, key)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Decrypted: %s\n", decrypted)
}
