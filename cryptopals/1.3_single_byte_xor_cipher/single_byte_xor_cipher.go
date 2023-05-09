package singlebytexorcipher

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"

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

func crackXorCipher(cipherBytes []byte, englishLetterFreqs map[byte]float64) ([]byte, error) {
	cipherByteLen := len(cipherBytes)
	if cipherByteLen == 0 {
		return nil, fmt.Errorf("error input must not be empty")
	}

	bestGuess := make([]byte, cipherByteLen)
	bestScore := 0.0

	for candidateKey := 0; candidateKey < 256; candidateKey++ {
		fullKey := bytes.Repeat([]byte{byte(candidateKey)}, cipherByteLen)
		plaintext, err := Xor(fullKey, cipherBytes)
		if err != nil {
			fmt.Printf("error xoring ciphertext and full key at candidate key %q: %v", candidateKey, err)
			continue
		}
		score := utils.FrequencyScore(plaintext, englishLetterFreqs)

		if score < bestScore || candidateKey == 0 {
			bestGuess = plaintext
			bestScore = score
		}
	}

	return bestGuess, nil
}

func Crack(ciphertext string, frequencyFilePath string, frequencyDirPath string) (string, error) {
	// Read frequency file
	jsonData, err := os.ReadFile(path.Join(frequencyDirPath, frequencyFilePath))
	if err != nil {
		return "", err
	}

	freqs := make(map[byte]float64)
	if err := json.Unmarshal(jsonData, &freqs); err != nil {
		return "", err
	}

	// Decode ciphertext from hex string to byte array
	cipherBytes, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	// Crack ciphertext
	plaintext, err := crackXorCipher(cipherBytes, freqs)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
