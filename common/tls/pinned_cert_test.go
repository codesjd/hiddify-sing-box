package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"testing"
	"time"
)

func selfSignedDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pinned-cert-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return der
}

func TestVerifyPinnedCertificateSha256Match(t *testing.T) {
	der := selfSignedDER(t)
	hash := sha256.Sum256(der)
	pin := hex.EncodeToString(hash[:])

	if err := VerifyPinnedCertificateSha256([]string{pin}, [][]byte{der}); err != nil {
		t.Fatalf("expected match, got error: %v", err)
	}
}

const zeroPin = "0000000000000000000000000000000000000000000000000000000000000000"

func TestVerifyPinnedCertificateSha256Mismatch(t *testing.T) {
	der := selfSignedDER(t)

	if err := VerifyPinnedCertificateSha256([]string{zeroPin[:64]}, [][]byte{der}); err == nil {
		t.Fatal("expected error for mismatched pin, got nil")
	}
}

func TestVerifyPinnedCertificateSha256MultiplePins(t *testing.T) {
	der := selfSignedDER(t)
	hash := sha256.Sum256(der)
	pin := hex.EncodeToString(hash[:])
	otherPin := zeroPin[:64]

	// The real pin among several - order shouldn't matter, and unrelated entries are ignored.
	if err := VerifyPinnedCertificateSha256([]string{otherPin, pin}, [][]byte{der}); err != nil {
		t.Fatalf("expected match among multiple pins, got error: %v", err)
	}
}

func TestVerifyPinnedCertificateSha256MalformedPinsSkipped(t *testing.T) {
	der := selfSignedDER(t)
	hash := sha256.Sum256(der)
	pin := hex.EncodeToString(hash[:])

	// "not-hex" is not valid hex and must be skipped rather than erroring out the whole check;
	// the valid pin alongside it should still match.
	if err := VerifyPinnedCertificateSha256([]string{"not-hex", pin}, [][]byte{der}); err != nil {
		t.Fatalf("expected match despite a malformed pin in the list, got error: %v", err)
	}

	// All-malformed must fail closed (not silently succeed).
	if err := VerifyPinnedCertificateSha256([]string{"not-hex", "also not hex"}, [][]byte{der}); err == nil {
		t.Fatal("expected error when every pin is malformed, got nil")
	}
}

func TestVerifyPinnedCertificateSha256NoPeerCert(t *testing.T) {
	if err := VerifyPinnedCertificateSha256([]string{"aa"}, nil); err == nil {
		t.Fatal("expected error for empty rawCerts, got nil")
	}
}
