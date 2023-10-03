package encryption_util

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
)

type EncryptionUtil struct{}

func NewEncryptionUtil() *EncryptionUtil {
	return &EncryptionUtil{}
}

func (e *EncryptionUtil) AesEncryptFromBase64(clearText, keyBase64 string, iv []byte) (string, error) {

	key, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if iv == nil {
		iv = make([]byte, aes.BlockSize)
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return "", err
		}
	}

	stream := cipher.NewCTR(block, iv)

	paddedText, err := pkcs7Pad([]byte(clearText), aes.BlockSize)
	if err != nil {
		return "", err
	}

	cipherText := make([]byte, len(paddedText))
	stream.XORKeyStream(cipherText, paddedText)

	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func (e *EncryptionUtil) AesDecryptFromBase64(encryptedText, selfEncryptionKeyBase64 string, iv []byte) (string, error) {
	cipherText, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		return "", err
	}

	key, err := base64.StdEncoding.DecodeString(selfEncryptionKeyBase64)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if iv == nil {
		iv = make([]byte, aes.BlockSize)
	}

	stream := cipher.NewCTR(block, iv)

	plainText := make([]byte, len(cipherText))
	stream.XORKeyStream(plainText, cipherText)

	unpaddedText, err := pkcs7Unpad([]byte(plainText), aes.BlockSize)
	if err != nil {
		return "", err
	}

	return string(unpaddedText), nil
}

// pkcs7strip remove pkcs7 padding
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("pkcs7: Data is empty")
	}
	if length%blockSize != 0 {
		return nil, errors.New("pkcs7: Data is not block-aligned")
	}
	padLen := int(data[length-1])
	ref := bytes.Repeat([]byte{byte(padLen)}, padLen)
	if padLen > blockSize || padLen == 0 || !bytes.HasSuffix(data, ref) {
		return nil, errors.New("pkcs7: Invalid padding")
	}
	return data[:length-padLen], nil
}

// pkcs7pad add pkcs7 padding
func pkcs7Pad(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 1 || blockSize >= 256 {
		return nil, fmt.Errorf("pkcs7: Invalid block size %d", blockSize)
	} else {
		padLen := blockSize - len(data)%blockSize
		padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
		return append(data, padding...), nil
	}
}

func (e *EncryptionUtil) GenerateRSAKeyPair() ([]byte, []byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	publicKeyBytes := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return privateKeyBytes, publicKeyBytes, nil
}

func (e *EncryptionUtil) GenerateAESKeyBase64() (string, error) {
	// AES-256 -> 32 bytes
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

func (e *EncryptionUtil) RsaDecryptFromBase64(cipherText string, privateKeyBytes []byte) (string, error) {
	block, _ := pem.Decode(privateKeyBytes)
	if block == nil {
		return "", fmt.Errorf("failed to decode private key")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}

	cipherBytes, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	decryptedBytes, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey.(*rsa.PrivateKey), cipherBytes)
	if err != nil {
		return "", err
	}

	return string(decryptedBytes), nil
}

func (e *EncryptionUtil) RsaEncryptToBase64(clearText string, publicKeyBytes []byte) (string, error) {
	block, _ := pem.Decode(publicKeyBytes)
	if block == nil {
		return "", fmt.Errorf("failed to decode public key")
	}

	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return "", err
	}

	encryptedBytes, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, []byte(clearText))
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(encryptedBytes), nil
}

func (e *EncryptionUtil) SignSHA256RSA(inputData string, privateKeyBytes []byte) (string, error) {
	privateKey, err := e.PrivateKeyFromBase64(string(privateKeyBytes))
	if err != nil {
		return "", err
	}

	hashed := sha256.Sum256([]byte(inputData))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

func (e *EncryptionUtil) PrivateKeyFromBase64(s string) (*rsa.PrivateKey, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(keyBytes)
	if err != nil {
		return nil, err
	}

	return privateKey.(*rsa.PrivateKey), nil
}

func (e *EncryptionUtil) PublicKeyFromBase64(s string) (*rsa.PublicKey, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode public key")
	}

	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}
