package hex_to_base64

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// HexToBase64 converts a hex string to base64 string
func HexToBase64(hexStr string) (string, error) {
	b, err := hex.DecodeString(hexStr) // Decode hex string to byte array
	if err != nil {
		return "", fmt.Errorf("error decoding hex string: %s", err)
	}

	return base64.StdEncoding.EncodeToString(b), nil // Convert byte array to base64 string
}
