package detectsinglecharacterxor

import (
	"fmt"
	"regexp"
	"strings"

	singlebytexorcipher "cryptography-challenge/1.3_single_byte_xor_cipher"
)

func isASCII(s string) bool {
	for _, c := range s {
		if c > 127 {
			return false
		}
	}
	return true
}

func isEnglish(s string) bool {
	r := regexp.MustCompile("[a-zA-Z]+")
	matches := r.FindAllString(s, -1)
	wordCount := 0
	characterCount := 0

	for _, match := range matches {
		characterCount += len(match)
		if isASCII(match) {
			wordCount++
		}
	}

	return float64(wordCount)/float64(len(matches)) > 0.8 && float64(characterCount)/float64(len(s)) > 0.7
}

func FindEnglish(ciphertext string) (string, error) {
	ciphertextList := strings.Split(ciphertext, "\n")

	for _, ciphertext := range ciphertextList {
		plaintext, err := singlebytexorcipher.Crack(ciphertext, "frequency.json", "../1.3_single_byte_xor_cipher")
		if err != nil {
			fmt.Printf("error when cracking %q: %v\n", ciphertext, err)
			continue
		}
		if isEnglish(plaintext) {
			return plaintext, nil
		}
	}

	return "", nil
}
