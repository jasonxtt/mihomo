package ca

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

const publicKeyPinPrefix = "spki-sha256:"

// NewFingerprintVerifier returns a function that verifies whether a certificate's SHA-256 fingerprint matches the given one.
func NewFingerprintVerifier(fingerprint string, time func() time.Time) (func(certs []*x509.Certificate, serverName string) error, error) {
	if pins, ok := strings.CutPrefix(fingerprint, publicKeyPinPrefix); ok {
		return newPublicKeyPinVerifier(pins)
	}
	switch fingerprint {
	case "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized": // WTF???
		return nil, fmt.Errorf("`fingerprint` is used for TLS certificate pinning. If you need to specify the browser fingerprint, use `client-fingerprint`")
	}
	fingerprint = strings.TrimSpace(strings.Replace(fingerprint, ":", "", -1))
	fpByte, err := hex.DecodeString(fingerprint)
	if err != nil {
		return nil, fmt.Errorf("fingerprint string decode error: %w", err)
	}

	if len(fpByte) != 32 {
		return nil, fmt.Errorf("fingerprint string length error,need sha256 fingerprint")
	}

	return func(certs []*x509.Certificate, serverName string) error {
		// ssl pining
		for i, cert := range certs {
			hash := sha256.Sum256(cert.Raw)
			if bytes.Equal(fpByte, hash[:]) {
				if i > 0 {
					// When the fingerprint matches a non-leaf certificate,
					// the certificate chain validity is verified using the certificate as the trusted root certificate.
					opts := x509.VerifyOptions{
						Roots:         x509.NewCertPool(),
						Intermediates: x509.NewCertPool(),
						DNSName:       serverName,
					}
					if time != nil {
						opts.CurrentTime = time()
					}
					opts.Roots.AddCert(certs[i])
					for _, cert := range certs[1 : i+1] { // stop at i
						opts.Intermediates.AddCert(cert)
					}
					_, err := certs[0].Verify(opts)
					return err
				}
				return nil
			}
		}
		return errNotMatch
	}, nil
}

func newPublicKeyPinVerifier(encodedPins string) (func([]*x509.Certificate, string) error, error) {
	var pins [][sha256.Size]byte
	for index, encoded := range strings.Split(encodedPins, ",") {
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(decoded) != sha256.Size {
			return nil, fmt.Errorf("invalid SHA-256 public key pin at position %d", index+1)
		}
		pins = append(pins, [sha256.Size]byte(decoded))
	}
	return func(certs []*x509.Certificate, _ string) error {
		if len(certs) == 0 {
			return fmt.Errorf("public key pin verification requires a leaf certificate")
		}
		publicKey, err := x509.MarshalPKIXPublicKey(certs[0].PublicKey)
		if err != nil {
			return fmt.Errorf("encode leaf public key: %w", err)
		}
		actual := sha256.Sum256(publicKey)
		for _, pin := range pins {
			if pin == actual {
				return nil
			}
		}
		return errNotMatch
	}, nil
}

// CalculateFingerprint computes the SHA-256 fingerprint of the given DER-encoded certificate and returns it as a hex string.
func CalculateFingerprint(certDER []byte) string {
	hash := sha256.Sum256(certDER)
	return hex.EncodeToString(hash[:])
}
