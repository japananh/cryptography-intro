package single_byte_xor_cipher

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path"
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
	defer func() {
		if err := file.Close(); err != nil {
			fmt.Printf("error when closing file: %v\n", err)
		}
	}()

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
