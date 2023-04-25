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

func encrypt(key, iv, plaintext []byte) ([]byte, error) {
	// Create AES block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create the OFB stream with the IV and AES cipher
	stream := cipher.NewOFB(block, iv)

	// Encrypt the plaintext
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)

	return ciphertext, nil
}

func decrypt(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create the OFB stream with the IV and AES cipher
	stream := cipher.NewOFB(block, iv)

	// Decrypt the ciphertext
	stream = cipher.NewOFB(block, iv)
	decrypted := make([]byte, len(ciphertext))
	stream.XORKeyStream(decrypted, ciphertext)

	return decrypted, nil
}

func main() {
	plaintext := []byte("Hello, world!")

	fmt.Printf("Plaintext: %s\n", plaintext)

	// Create the AES cipher using a 32 byte key
	key, err := generateAESKey(32)
	if err != nil {
		panic(err)
	}

	// Create a 16 byte random initialization vector
	iv, err := generateIV(aes.BlockSize)
	if err != nil {
		panic(err)
	}

	// Encrypt the plaintext
	ciphertext, err := encrypt(key, iv, plaintext)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Encrypted: %x\n", ciphertext)

	// Decrypt the ciphertext
	decrypted, err := decrypt(key, iv, ciphertext)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Decrypted: %s\n", decrypted)
}
