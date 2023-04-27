package single_byte_xor_cipher

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"math"
	"os"
)

func readFile(filePath string, dirPath string) ([]byte, error) {
	if filePath == "" {
		return nil, fmt.Errorf("error file path cannot be empty")
	}

	// Get current working directory
	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("error getting current working directory: %v", err)
	}

	if dirPath == "" {
		dirPath = cwd
	}

	// Change working directory to given directory path
	if err := os.Chdir(dirPath); err != nil {
		return nil, fmt.Errorf("error changing working directory: %v", err)
	}

	// Check if the file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("error file does not exist: %v", err)
	}

	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %v", err)
	}
	defer file.Close()

	// Create a byte buffer to store the file contents
	var buffer bytes.Buffer

	// Read file line by line
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// Append each line to the buffer
		buffer.Write(scanner.Bytes())
	}

	// Check for any errors during scanning
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Change back to original working directory
	if err := os.Chdir(cwd); err != nil {
		return nil, fmt.Errorf("error changing working directory back: %v", cwd)
	}

	// Return the contents of the file as a slice of bytes
	return buffer.Bytes(), nil
}

func asciiFrequency(data []byte) map[byte]float64 {
	countMap := make(map[byte]int)
	freqMap := make(map[byte]float64)
	totalChars := len(data)

	// Create an array byte of all ASCII characters
	// ASCII code runs from 0 (`null`) to 127 (`del`)
	for i := 0; i <= 127; i++ {
		countMap[byte(i)] = 0
	}

	for _, b := range data {
		if b >= 0 && b <= 127 {
			countMap[b]++
		}
	}

	for k, v := range countMap {
		freqMap[k] = float64(v) / float64(totalChars)
	}

	return freqMap
}

func getByteFrequency(b byte, data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}

	freq := 0
	for _, item := range data {
		if item == b {
			freq++
		}
	}

	return float64(freq) / float64(len(data))
}

func scoreCharacter(data []byte, freqs map[byte]float64) float64 {
	if len(data) == 0 {
		return 0.0
	}

	score := 0.0

	for c, freqExpected := range freqs {
		freqActual := getByteFrequency(c, data)
		diff := math.Abs(freqExpected - freqActual)
		score += diff
	}

	return score
}

func xor(b1, b2 []byte) ([]byte, error) {
	if len(b1) != len(b2) {
		return nil, fmt.Errorf("input must have same length")
	}

	out := make([]byte, len(b1))
	for i := range b1 {
		out[i] = b1[i] ^ b2[i]
	}

	return out, nil
}

func crackXorCipher(cipherbytes []byte, freqs map[byte]float64) ([]byte, error) {
	if len(cipherbytes) == 0 {
		return nil, fmt.Errorf("error input must not be empty")
	}

	bestGuess := make([]byte, len(cipherbytes))
	bestScore := 0.0

	for candidateKey := 0; candidateKey <= 256; candidateKey++ {
		fullKey := bytes.Repeat([]byte{byte(candidateKey)}, len(cipherbytes))
		plaintext, err := xor(fullKey, cipherbytes)
		if err != nil {
			fmt.Printf("error xoring ciphertext and full key: %v", err)
			continue
		}
		score := scoreCharacter(plaintext, freqs)

		if score <= bestScore || candidateKey == 0 {
			bestGuess = plaintext
			bestScore = score
		}
	}

	return bestGuess, nil
}

var ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

func Crack(ciphertext string) (string, error) {
	// Create frequencies from
	fileContent, err := readFile("frequency.txt", "")
	if err != nil {
		return "", err
	}
	freqs := asciiFrequency(fileContent)

	// Decode hex string to byte array
	cipherBytes, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	// Crack cipher
	plaintext, err := crackXorCipher(cipherBytes, freqs)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
