package agessh

import (
	"crypto"
	"crypto/ed25519"
	"crypto/sha512"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strings"

	"filippo.io/edwards25519"
	"github.com/Mic92/ssh-to-age/bech32"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ssh"
)

var (
	UnsupportedKeyType = errors.New("only ed25519 keys are supported")
)

func ed25519PrivateKeyToCurve25519(pk ed25519.PrivateKey) ([]byte, error) {
	h := sha512.New()
	_, err := h.Write(pk.Seed())
	if err != nil {
		return []byte{}, err
	}
	out := h.Sum(nil)
	return out[:curve25519.ScalarSize], nil
}

func ed25519PublicKeyToCurve25519(pk ed25519.PublicKey) ([]byte, error) {
	// See https://blog.filippo.io/using-ed25519-keys-for-encryption and
	// https://pkg.go.dev/filippo.io/edwards25519#Point.BytesMontgomery.
	p, err := new(edwards25519.Point).SetBytes(pk)
	if err != nil {
		return nil, err
	}
	return p.BytesMontgomery(), nil
}

func encodePublicKey(key crypto.PublicKey) (*string, error) {
	epk, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("BUG! public key is not of type ed25519.PublicKey: %s", reflect.TypeOf(key))
	}
	// Convert the key to curve ed25519
	mpk, err := ed25519PublicKeyToCurve25519(epk)
	if err != nil {
		return nil, fmt.Errorf("cannot convert ed25519 public key to curve25519: %w", err)
	}
	// Encode the key
	s, err := bech32.Encode("age", mpk)
	if err != nil {
		return nil, fmt.Errorf("cannot encode key as bech32: %w", err)
	}
	return &s, nil
}

func SSHPrivateKeyToAge(sshKey, passphrase []byte) (*string, *string, error) {
	var (
		privateKey interface{}
		err        error
	)
	if len(passphrase) > 0 {
		privateKey, err = ssh.ParseRawPrivateKeyWithPassphrase(sshKey, passphrase)
	} else {
		privateKey, err = ssh.ParseRawPrivateKey(sshKey)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse ssh private key: %w", err)
	}

	ed25519Key, ok := privateKey.(*ed25519.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("got %s key type but: %w", reflect.TypeOf(privateKey), UnsupportedKeyType)
	}

	pubKey, err := encodePublicKey(ed25519Key.Public())
	if err != nil {
		return nil, nil, err
	}
	bytes, err := ed25519PrivateKeyToCurve25519(*ed25519Key)
	if err != nil {
		return nil, nil, err
	}

	s, err := bech32.Encode("AGE-SECRET-KEY-", bytes)
	if err != nil {
		return nil, nil, err
	}
	s = strings.ToUpper(s)
	return &s, pubKey, nil
}

func SSHPublicKeyToAge(sshKey []byte) (*string, error) {
	var err error
	var pk ssh.PublicKey
	if strings.HasPrefix(string(sshKey), "ssh-") {
		pk, _, _, _, err = ssh.ParseAuthorizedKey(sshKey)
	} else {
		_, _, pk, _, _, err = ssh.ParseKnownHosts(sshKey)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to parse ssh public key: %w", err)
	}
	// We only care about ed25519
	if pk.Type() != ssh.KeyAlgoED25519 {
		return nil, fmt.Errorf("got %s key type, but %w", pk.Type(), UnsupportedKeyType)
	}
	// Get the bytes
	cpk, ok := pk.(ssh.CryptoPublicKey)
	if !ok {
		return nil, errors.New("BUG! public key does not implement ssh.CryptoPublicKey")
	}
	return encodePublicKey(cpk.CryptoPublicKey())
}

func AgeToSSH(ageKey string) ([]string, error) {
	ageKey = strings.TrimSpace(ageKey)
	if ageKey == "" {
		return nil, nil
	}

	hrp, data, err := bech32.Decode(ageKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key %s: %v", ageKey, err)
	}

	if hrp != "age" {
		return nil, fmt.Errorf("invalid HRP: expected \"age\", got \"%s\"", hrp)
	}

	if len(data) != 32 {
		return nil, fmt.Errorf("invalid key length: expected 32 bytes, got %d", len(data))
	}

	// Convert Curve25519 (Montgomery) u to Ed25519 (Edwards) y
	// y = (u - 1) / (u + 1) mod p
	// p = 2^255 - 19

	// data is little-endian u coordinate. Convert to big-endian for big.Int
	uBytes := make([]byte, 32)
	copy(uBytes, data)
	reverse(uBytes)
	u := new(big.Int).SetBytes(uBytes)

	p, _ := new(big.Int).SetString("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16)

	one := big.NewInt(1)

	// num = u - 1
	num := new(big.Int).Sub(u, one)

	// den = u + 1
	den := new(big.Int).Add(u, one)

	// invDen = den^-1 mod p
	invDen := new(big.Int).ModInverse(den, p)

	if invDen == nil {
		return nil, fmt.Errorf("singular point (u=-1)")
	}

	// y = num * invDen mod p
	y := new(big.Int).Mul(num, invDen)
	y.Mod(y, p)

	// Convert y to 32 bytes little-endian
	yBytes := y.Bytes()
	// Pad to 32 bytes if necessary (big.Int.Bytes() returns minimal byte slice)
	if len(yBytes) < 32 {
		padding := make([]byte, 32-len(yBytes))
		yBytes = append(padding, yBytes...)
	}

	// big.Int.Bytes() returns big-endian. We need little-endian for Ed25519.
	reverse(yBytes)

	// Candidate 1: sign bit 0
	pubKey1 := make([]byte, 32)
	copy(pubKey1, yBytes)
	// The highest bit of the last byte is already 0 because p < 2^255

	// Candidate 2: sign bit 1
	pubKey2 := make([]byte, 32)
	copy(pubKey2, yBytes)
	pubKey2[31] |= 0x80

	sshKey1, err := formatSSHKey(pubKey1)
	if err != nil {
		return nil, err
	}
	sshKey2, err := formatSSHKey(pubKey2)
	if err != nil {
		return nil, err
	}

	return []string{sshKey1, sshKey2}, nil
}

func reverse(b []byte) {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
}

func formatSSHKey(pubKeyBytes []byte) (string, error) {
	pk := ed25519.PublicKey(pubKeyBytes)

	sshPub, err := ssh.NewPublicKey(pk)
	if err != nil {
		return "", fmt.Errorf("failed to create SSH public key: %v", err)
	}

	// ssh.MarshalAuthorizedKey appends a newline
	keyStr := string(ssh.MarshalAuthorizedKey(sshPub))
	return strings.TrimSpace(keyStr), nil
}
