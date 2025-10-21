package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"os"
)

// Key: b457241d8d191fe544ad0f2dabba1619d53ae6b2918aea9c8c8c4bf75f65dfa5
func main() {
	// Prompt user to enter the decryption key
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter the 32-byte hex key for decryption: ")
	keyString, _ := reader.ReadString('\n')
	keyString = keyString[:len(keyString)-1] // Remove newline character

	// Prompt user to enter the encrypted text
	fmt.Print("Enter the encrypted text: ")
	encryptedString, _ := reader.ReadString('\n')
	encryptedString = encryptedString[:len(encryptedString)-1] // Remove newline character

	// Perform decryption
	decrypted := decrypt(encryptedString, keyString)
	fmt.Printf("Decrypted: %s\n", decrypted)
}

func decrypt(encryptedString string, keyString string) (decryptedString string) {
	key, _ := hex.DecodeString(keyString)
	enc, _ := hex.DecodeString(encryptedString)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	nonceSize := aesGCM.NonceSize()
	nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	return string(plaintext)
}
