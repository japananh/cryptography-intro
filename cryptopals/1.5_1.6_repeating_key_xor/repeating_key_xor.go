package repeating_key_xor

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"math/bits"

	singlebytexorcipher "cryptography-challenge/1.3_single_byte_xor_cipher"
	"cryptography-challenge/utils"
)

func Encrypt(s string, key string) string {
	if key == "" || s == "" {
		return s
	}

	cipher := make([]byte, len(s))
	for i := range s {
		cipher[i] = s[i] ^ key[i%len(key)]
	}

	return hex.EncodeToString(cipher)
}

/*
* hammingDistance Calculate the Hamming distance between two byte slices.
* Hamming distance is the number of different bits between two strings with the same length.
* Example: the hamming distance between `kathrin` and `karolin` is 9
* kathrin:          01101011 01100001 01110010 01101111 01101100 01101001 01101110
* karolin:          01101011 01100001 01110100 01101000 01110010 01101001 01101110
* hamming distance: 0 +      0 +      2 +      3 +      4 +      0 +      0       = 9
 */
func hammingDistance(a, b []byte) int {
	if len(a) != len(b) {
		return -1
	}
	var distance int
	for i := 0; i < len(a); i++ {
		xor := a[i] ^ b[i]
		distance += bits.OnesCount64(uint64(xor))
	}
	return distance
}

// avgHammingDistance Calculate the average Hamming distance between blocks of a given size in a byte slice
func avgHammingDistance(data []byte, keySize int) float64 {
	// The block size must be less than or equal to the length of data
	if keySize > len(data) {
		return -1
	}
	var totalDistance float64
	blockCount := len(data) / keySize
	for i := 0; i < blockCount-1; i++ {
		a := data[i*keySize : (i+1)*keySize]
		b := data[(i+1)*keySize : (i+2)*keySize]
		distance := hammingDistance(a, b)
		normalizedDistance := float64(distance) / float64(keySize)
		totalDistance += normalizedDistance
	}
	return totalDistance / float64(blockCount-1)
}

// findKeySize Find the key size with the smallest normalized Hamming distance
func findKeySize(ciphertext []byte, minKeySize, maxKeySize int) int {
	var keySize int
	var minDistance = math.MaxFloat64
	for size := minKeySize; size <= maxKeySize; size++ {
		distance := avgHammingDistance(ciphertext, size)
		if distance < minDistance {
			keySize = size
			minDistance = distance
		}
	}
	return keySize
}

// findCipherKey Find cipher key
func findCipherKey(ciphertext []byte, minKeySize, maxKeySize int) ([]byte, error) {
	if maxKeySize == 0 || minKeySize == 0 {
		return nil, fmt.Errorf("key size must be greater than 0")
	}

	if ciphertext == nil || len(ciphertext) == 0 {
		return ciphertext, nil
	}

	// Find key size
	keySize := findKeySize(ciphertext, minKeySize, maxKeySize)

	// Transpose blocks to make
	transposedBlocks := make([][]byte, keySize)
	for i := 0; i < len(ciphertext); i++ {
		transposedBlocks[i%keySize] = append(transposedBlocks[i%keySize], ciphertext[i])
	}

	// Get English letter frequency dict
	englishLetterFrequencies, err := utils.GetEnglishLetterFrequency("../utils", "frequency.json")
	if err != nil {
		return nil, err
	}

	key := make([]byte, keySize)
	for i, block := range transposedBlocks {
		_, c, err := singlebytexorcipher.Crack(block, englishLetterFrequencies)
		if err != nil {
			return nil, err
		}
		key[i] = c
	}

	return key, nil
}

// Crack Break a repeating-key XOR cipher
func Crack(ciphertext []byte) ([]byte, error) {
	key, err := findCipherKey(ciphertext, 2, 40)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(ciphertext))
	for i := range ciphertext {
		plaintext[i] = ciphertext[i] ^ key[i%len(key)]
	}

	return plaintext, nil
}

// CrackFromBase64 Break a repeating-key XOR cipher from base64 string
func CrackFromBase64(ciphertextBase64 string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return nil, err
	}

	return Crack(ciphertext)
}
