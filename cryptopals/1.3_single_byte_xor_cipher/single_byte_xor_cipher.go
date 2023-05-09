package singlebytexorcipher

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"cryptography-challenge/utils"
)

func Xor(b1, b2 []byte) ([]byte, error) {
	if len(b1) != len(b2) {
		return nil, fmt.Errorf("input must have same length")
	}

	out := make([]byte, len(b1))
	for i := range b1 {
		out[i] = b1[i] ^ b2[i]
	}

	return out, nil
}

// Crack Breaks single-byte XOR cipher
func Crack(cipherBytes []byte, englishLetterFreqs map[byte]float64) (plaintext []byte, key byte, err error) {
	cipherByteLen := len(cipherBytes)
	if cipherByteLen == 0 {
		return nil, 0, fmt.Errorf("error input must not be empty")
	}

	bestScore := 0.0

	for candidateKey := 0; candidateKey < 256; candidateKey++ {
		fullKey := bytes.Repeat([]byte{byte(candidateKey)}, cipherByteLen)
		guess, err := Xor(fullKey, cipherBytes)
		if err != nil {
			fmt.Printf("error xoring ciphertext and full key at candidate key %q: %v", candidateKey, err)
			continue
		}
		score := utils.FrequencyScore(guess, englishLetterFreqs)

		if score < bestScore || candidateKey == 0 {
			plaintext = guess
			bestScore = score
			key = byte(candidateKey)
		}
	}

	return plaintext, key, nil
}

// CrackFromHex Breaks single-byte XOR cipher from hex input
func CrackFromHex(ciphertext string, englishLetterFreqs map[byte]float64) (plaintext []byte, key byte, err error) {
	if ciphertext == "" {
		return nil, 0, fmt.Errorf("error input must not be empty")
	}

	// Decode ciphertext from hex string to byte array
	cipherBytes, err := hex.DecodeString(ciphertext)
	if err != nil {
		fmt.Printf("error when decoding %q: %v", ciphertext, err)
		return nil, 0, fmt.Errorf("error when decoding %q: %v", ciphertext, err)
	}

	bestScore := 0.0

	for candidateKey := 0; candidateKey < 256; candidateKey++ {
		fullKey := bytes.Repeat([]byte{byte(candidateKey)}, len(cipherBytes))
		guess, err := Xor(fullKey, cipherBytes)
		if err != nil {
			fmt.Printf("error xoring ciphertext and full key at candidate key %q: %v", candidateKey, err)
			continue
		}
		score := utils.FrequencyScore(guess, englishLetterFreqs)

		if score < bestScore || candidateKey == 0 {
			plaintext = guess
			bestScore = score
			key = byte(candidateKey)
		}
	}

	return plaintext, key, nil
}
