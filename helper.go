package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"github.com/golang-jwt/jwt/v5"
	"log"
	"net/http"
	"time"
)

const SecretKey string = "6BDwUHOJIHOj8kyHTEBdFVRyrTkwRGJB"

// Encrypt password function using AES
func encryptPassword(password string) string {
	block, err := aes.NewCipher([]byte(SecretKey))
	if err != nil {
		log.Println("Error: ", err)
	}
	passwordBytes := []byte(password)
	ciphertext := make([]byte, aes.BlockSize+len(passwordBytes))
	iv := ciphertext[:aes.BlockSize]
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], passwordBytes)
	encodedCiphertext := base64.StdEncoding.EncodeToString(ciphertext)
	return encodedCiphertext
}

// Decrypt password function using AES
func decryptPassword(encodedCiphertext string) string {
	block, err := aes.NewCipher([]byte(SecretKey))
	if err != nil {
		log.Println("Error: ", err)
	}
	decodedCiphertext, err := base64.StdEncoding.DecodeString(encodedCiphertext)
	if err != nil {
		log.Println("Error: ", err)
	}

	if len(decodedCiphertext) < aes.BlockSize {
		log.Println("Error: ciphertext too short")
	}

	iv := decodedCiphertext[:aes.BlockSize]
	decodedCiphertext = decodedCiphertext[aes.BlockSize:]

	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(decodedCiphertext, decodedCiphertext)

	password := string(decodedCiphertext)
	log.Println("Password: ", password)
	return password
}

// createToken function to create a jwt token
func createToken(username string) (string, error) {
	// If authentication is successful, generate a JWT token
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["sub"] = username
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix()
	tokenString, err := token.SignedString([]byte(SecretKey))
	if err != nil {
		log.Println("Error: ", err)
		return "", err
	}
	log.Println("Token: ", tokenString)
	return tokenString, nil
}

// SetDBMiddleware function to set the database middleware
func SetDBMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timeoutContext, _ := context.WithTimeout(context.Background(), time.Second)
		ctx := context.WithValue(r.Context(), "DB", db.WithContext(timeoutContext))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
