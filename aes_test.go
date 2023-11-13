package crypto_test

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"

	"github.com/japananh/crypto"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("crypto - aes", func() {
	generateRandomKey := func(size int) []byte {
		b := make([]byte, size)
		_, err := rand.Read(b)
		Expect(err).NotTo(HaveOccurred())
		return b
	}

	Describe("AESGCMEncrypt - AESGCMDecrypt", func() {
		Context("with valid inputs", func() {
			Context("with small plaintext and 16-byte key", func() {
				It("should encrypt and decrypt correctly", func() {
					plaintext := []byte("{ \"id\": \"1w$5422w#344aewbj33242\" }")
					buf := bytes.NewReader(plaintext)
					keySize := 32
					key := generateRandomKey(keySize)

					ciphertext, err := crypto.AESGCMEncrypt(buf, key)

					Expect(err).NotTo(HaveOccurred())
					Expect(ciphertext).NotTo(BeNil())

					decryptedText, err := crypto.AESGCMDecrypt(bytes.NewReader(ciphertext), key)

					Expect(err).NotTo(HaveOccurred())
					Expect(decryptedText).To(Equal(plaintext))
				})
			})

			Context("with small plaintext and 24-byte key", func() {
				It("should encrypt and decrypt correctly", func() {
					plaintext := []byte("{ \"id\": \"1w$5422w#344aewbj33242\" }")
					buf := bytes.NewReader(plaintext)
					keySize := 24
					key := generateRandomKey(keySize)

					ciphertext, err := crypto.AESGCMEncrypt(buf, key)

					Expect(err).NotTo(HaveOccurred())
					Expect(ciphertext).NotTo(BeNil())

					decryptedText, err := crypto.AESGCMDecrypt(bytes.NewReader(ciphertext), key)

					Expect(err).NotTo(HaveOccurred())
					Expect(decryptedText).To(Equal(plaintext))
				})
			})

			Context("with small plaintext and 32-byte key", func() {
				It("should encrypt and decrypt correctly", func() {
					plaintext := []byte("{ \"id\": \"1w$5422w#344aewbj33242\" }")
					buf := bytes.NewReader(plaintext)
					keySize := 32
					key := generateRandomKey(keySize)

					ciphertext, err := crypto.AESGCMEncrypt(buf, key)

					Expect(err).NotTo(HaveOccurred())
					Expect(ciphertext).NotTo(BeNil())

					decryptedText, err := crypto.AESGCMDecrypt(bytes.NewReader(ciphertext), key)

					Expect(err).NotTo(HaveOccurred())
					Expect(decryptedText).To(Equal(plaintext))
				})
			})

			Context("with medium plaintext and 32-byte key", func() {
				It("should encrypt and decrypt correctly", func() {
					// Generate large JSON plaintext with ~ 7 MB
					largeJSONObject := make(map[string]string)
					for i := 0; i < 100000; i++ {
						largeJSONObject[fmt.Sprintf("key%d", i)] = "some long value that contributes to the size of the json"
					}
					largeJSONPlaintext, err := json.Marshal(largeJSONObject)
					fmt.Println(len(largeJSONPlaintext))
					Expect(err).NotTo(HaveOccurred())
					Expect(largeJSONPlaintext).NotTo(BeNil())

					buf := bytes.NewReader(largeJSONPlaintext)

					keySize := 16
					key := generateRandomKey(keySize)

					ciphertext, err := crypto.AESGCMEncrypt(buf, key)

					Expect(err).NotTo(HaveOccurred())
					Expect(ciphertext).NotTo(BeNil())

					decryptedText, err := crypto.AESGCMDecrypt(bytes.NewReader(ciphertext), key)

					Expect(err).NotTo(HaveOccurred())
					Expect(decryptedText).To(Equal(largeJSONPlaintext))
				})
			})

			When("The plaintext that is larger than the default chunk size", func() {
				Context("with very large plaintext and 32-byte AES key", func() {
					It("should encrypt and decrypt correctly", func() {
						// Generate large JSON plaintext with ~ 720 MB
						largeJSONObject := make(map[string]string)
						for i := 0; i < 10000000; i++ {
							largeJSONObject[fmt.Sprintf("key%d", i)] = "some long value that contributes to the size of the json"
						}
						largeJSONPlaintext, err := json.Marshal(largeJSONObject)

						Expect(err).NotTo(HaveOccurred())
						Expect(largeJSONPlaintext).NotTo(BeNil())

						buf := bytes.NewReader(largeJSONPlaintext)

						keySize := 32
						key := generateRandomKey(keySize)

						ciphertext, err := crypto.AESGCMEncrypt(buf, key)

						Expect(err).NotTo(HaveOccurred())
						Expect(ciphertext).NotTo(BeNil())

						decryptedText, err := crypto.AESGCMDecrypt(bytes.NewReader(ciphertext), key)

						Expect(err).NotTo(HaveOccurred())
						Expect(decryptedText).To(Equal(largeJSONPlaintext))
					})
				})
			})

			It("should handle empty plaintext correctly", func() {
				plaintext := []byte("")
				buf := bytes.NewReader(plaintext)
				keySize := 16
				key := generateRandomKey(keySize)

				ciphertext, err := crypto.AESGCMEncrypt(buf, key)

				Expect(err).NotTo(HaveOccurred())
				Expect(ciphertext).To(BeNil())

				decryptedText, err := crypto.AESGCMDecrypt(bytes.NewReader(ciphertext), key)

				Expect(err).NotTo(HaveOccurred())
				Expect(decryptedText).To(Equal(plaintext))
			})

			It("should handle nil plaintext correctly", func() {
				var plaintext []byte
				buf := bytes.NewReader(plaintext)
				keySize := 16
				key := generateRandomKey(keySize)

				ciphertext, err := crypto.AESGCMEncrypt(buf, key)

				Expect(err).NotTo(HaveOccurred())
				Expect(ciphertext).To(BeNil())

				decryptedText, err := crypto.AESGCMDecrypt(bytes.NewReader(ciphertext), key)

				Expect(err).NotTo(HaveOccurred())
				Expect(decryptedText).To(Equal(plaintext))
			})
		})

		Context("with invalid inputs", func() {
			When("key is nil", func() {
				It("should handle error", func() {
					plaintext := []byte("example plaintext")
					buf := bytes.NewReader(plaintext)
					var key []byte

					_, err := crypto.AESGCMEncrypt(buf, key)

					Expect(err).To(HaveOccurred())
				})
			})

			When("input an 8-byte key)", func() {
				It("should handle error", func() {
					plaintext := []byte("example plaintext")
					buf := bytes.NewReader(plaintext)
					key := generateRandomKey(8)

					_, err := crypto.AESGCMEncrypt(buf, key)

					Expect(err).To(HaveOccurred())
				})
			})
		})
	})
})
