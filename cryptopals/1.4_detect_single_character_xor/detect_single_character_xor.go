package detectsinglecharacterxor

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	singlebytexorcipher "cryptography-challenge/1.3_single_byte_xor_cipher"
	"cryptography-challenge/utils"
)

func isASCII(input []byte) bool {
	for _, c := range input {
		if c > 127 {
			return false
		}
	}
	return true
}

func isEnglish(input []byte) bool {
	r := regexp.MustCompile("[a-zA-Z]+")
	matches := r.FindAllString(string(input), -1)
	wordCount := 0
	characterCount := 0

	for _, match := range matches {
		characterCount += len(match)
		if isASCII([]byte(match)) {
			wordCount++
		}
	}

	return float64(wordCount)/float64(len(matches)) > 0.8 && float64(characterCount)/float64(len(input)) > 0.7
}

func FindEnglish(ciphertext string) (string, error) {
	ciphertextList := strings.Split(ciphertext, "\n")

	englishLetterFreqs, err := utils.GetEnglishLetterFrequency("../utils", "frequency.json")
	if err != nil {
		return "", err
	}

	for _, ciphertext := range ciphertextList {
		// Decode ciphertext from hex string to byte array
		cipherBytes, err := hex.DecodeString(ciphertext)
		if err != nil {
			fmt.Printf("error when decoding %q: %v", ciphertext, err)
			continue
		}
		plaintext, _, err := singlebytexorcipher.Crack(cipherBytes, englishLetterFreqs)
		if err != nil {
			fmt.Printf("error when cracking %q: %v", ciphertext, err)
			continue
		}
		if isEnglish(plaintext) {
			return string(plaintext), nil
		}
	}

	return "", nil
}
