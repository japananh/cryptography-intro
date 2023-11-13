package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// AESGCMChunkSize is the size of each chunk that will be encrypted with AES-GCM
// The max size supported ~ 65 GB. Ref: https://github.com/golang/go/blob/master/src/crypto/aes/aes_gcm.go#L95
const AESGCMChunkSize = 2 ^ 32 // 2^32 ~ 4.3 GB

// AESGCMEncrypt encrypts data using AES encryption with GCM mode.
func AESGCMEncrypt(buf io.Reader, key []byte) ([]byte, error) {
	// Generate a new AES cipher using the AES key, either 16, 24 or 32 bytes to select AES-128, AES-192, or AES-256.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create a new GCM cipher mode instance
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	var ciphertext []byte

	// Divide input into multiple chunks
	chunk := make([]byte, AESGCMChunkSize)

	for {
		n, err := buf.Read(chunk)
		if err == io.EOF || n == 0 {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read chunk: %v", err)
		}

		// Create a seperated random nonce for each chunk
		// Note: Using the same nonce for multiple chunks would be insecure
		nonce := make([]byte, gcm.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, err
		}

		// Encrypt each chunk with its own nonce
		encryptedChunk := gcm.Seal(chunk[:n][:0], nonce, chunk[:n], nil)

		// Add chunk nonce to the beginning of the encrypted chunk
		encryptedChunkWithNonce := append(nonce, encryptedChunk...)

		ciphertext = append(ciphertext, encryptedChunkWithNonce...)
	}

	return ciphertext, nil
}

// AESGCMDecrypt decrypts the data using encryption with GCM mode
func AESGCMDecrypt(buf io.Reader, key []byte) ([]byte, error) {
	// Generate a new AES cipher using the key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create a new GCM cipher mode instance
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	var plaintext []byte

	nonceSize := gcm.NonceSize()
	tagSize := gcm.Overhead()
	// After encryption, chunk size = default chunk size + nonce size + tag size
	chunkSize := AESGCMChunkSize + nonceSize + tagSize
	chunk := make([]byte, chunkSize)

	for {
		n, err := buf.Read(chunk)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read chunk: %w", err)
		}

		nonce := chunk[:nonceSize] // Extract nonce from the beginning of the chunk
		encryptedChunk := chunk[nonceSize:n]

		decryptedChunk, err := gcm.Open(encryptedChunk[:0], nonce, encryptedChunk, nil)
		if err != nil {
			return nil, err
		}

		plaintext = append(plaintext, decryptedChunk...)
	}

	return plaintext, nil
}
