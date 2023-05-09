package xor

import (
	"encoding/hex"
	"fmt"
)

func Xor(hexStr1, hexStr2 string) (string, error) {
	if hexStr1 == "" || hexStr2 == "" {
		return "", fmt.Errorf("input cannot be empty")
	}

	b1, err := hex.DecodeString(hexStr1)
	if err != nil {
		return "", fmt.Errorf("error when decode first string: %v", err)
	}

	b2, err := hex.DecodeString(hexStr2)
	if err != nil {
		return "", fmt.Errorf("error when decode second string: %v", err)
	}

	if len(b1) != len(b2) {
		return "", fmt.Errorf("input must have the same length")
	}

	out := make([]byte, len(b1))
	for i := range b1 {
		out[i] = b1[i] ^ b2[i]
	}

	return hex.EncodeToString(out), nil
}
