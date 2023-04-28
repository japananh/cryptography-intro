package repeating_key_xor

import (
	"encoding/hex"
)

func Encrypt(s string, key string) string {
	if key == "" || s == "" {
		return s
	}

	cipher := make([]byte, len(s))
	for i, _ := range s {
		cipher[i] = s[i] ^ key[i%len(key)]
	}

	return hex.EncodeToString(cipher)
}
