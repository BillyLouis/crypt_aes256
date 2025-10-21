package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// Key: b457241d8d191fe544ad0f2dabba1619d53ae6b2918aea9c8c8c4bf75f65dfa5
func main() {
	// Prompt user to enter the encryption key
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter a 32-byte hex key for encryption: ")
	keyString, _ := reader.ReadString('\n')
	keyString = keyString[:len(keyString)-1] // Remove newline character

	// Prompt user to enter the text to encrypt
	fmt.Print("Enter text to encrypt: ")
	textToEncrypt, _ := reader.ReadString('\n')
	textToEncrypt = textToEncrypt[:len(textToEncrypt)-1] // Remove newline character

	// Perform encryption
	encrypted := encrypt(textToEncrypt, keyString)
	fmt.Printf("Encrypted: %s\n", encrypted)
}

func encrypt(stringToEncrypt string, keyString string) (encryptedString string) {
	key, _ := hex.DecodeString(keyString)
	plaintext := []byte(stringToEncrypt)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)

	return fmt.Sprintf("%x", ciphertext)
}
