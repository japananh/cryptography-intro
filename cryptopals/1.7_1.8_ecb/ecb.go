package ecb

import (
	"crypto/aes"
	"encoding/base64"

	"cryptography-challenge/utils"
)

func Encrypt(plaintext, key []byte) ([]byte, error) {
	if plaintext == nil || len(plaintext) == 0 {
		return plaintext, nil
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	paddedText := utils.Pkcs7Pad(plaintext)
	ciphertext := make([]byte, len(paddedText))

	for i := 0; i < len(paddedText); i += block.BlockSize() {
		block.Encrypt(ciphertext[i:i+block.BlockSize()], paddedText[i:i+block.BlockSize()])
	}

	return ciphertext, nil
}

func Decrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(ciphertext))

	for i := 0; i < len(ciphertext); i += block.BlockSize() {
		block.Decrypt(plaintext[i:i+block.BlockSize()], ciphertext[i:i+block.BlockSize()])
	}

	return utils.Pkcs7Unpad(plaintext)
}

func DecryptFromBase64(ciphertext string, key []byte) ([]byte, error) {
	ciphertextBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}
	return Decrypt(ciphertextBytes, key)
}
