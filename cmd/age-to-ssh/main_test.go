package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	sshage "github.com/Mic92/ssh-to-age"
)

// ok fails the test if an err is not nil.
func ok(tb testing.TB, err error) {
	if err != nil {
		_, file, line, _ := runtime.Caller(1)
		fmt.Printf("\033[31m%s:%d: unexpected error: %s\033[39m\n\n", filepath.Base(file), line, err.Error())
		tb.FailNow()
	}
}

func Asset(name string) string {
	assets := os.Getenv("TEST_ASSETS")
	if assets == "" {
		// Assuming we run tests from cmd/age-to-ssh
		assets = "../ssh-to-age/test-assets"
	}
	return path.Join(assets, name)
}

func TempDir(t *testing.T) string {
	tempdir, err := ioutil.TempDir(os.TempDir(), "testdir")
	ok(t, err)
	return tempdir
}

func TestPublicKey(t *testing.T) {
	tempdir := TempDir(t)
	defer os.RemoveAll(tempdir)
	out := path.Join(tempdir, "out")
	in := path.Join(tempdir, "in")

	// Prepare input: convert ssh pub key to age key
	pubKeyPath := Asset("id_ed25519.pub")
	pubKeyBytes, err := ioutil.ReadFile(pubKeyPath)
	ok(t, err)
	sshPubKey := strings.TrimSpace(string(pubKeyBytes))

	ageKeyPtr, err := sshage.SSHPublicKeyToAge([]byte(sshPubKey))
	ok(t, err)

	err = ioutil.WriteFile(in, []byte(*ageKeyPtr), 0644)
	ok(t, err)

	err = convertKeys([]string{"age-to-ssh", "-i", in, "-o", out})
	ok(t, err)

	rawOutput, err := ioutil.ReadFile(out)
	ok(t, err)

	fmt.Printf("output:\n%s", string(rawOutput))

	// Verify one of the candidates matches
	found := false
	scanner := bufio.NewScanner(strings.NewReader(string(rawOutput)))
	for scanner.Scan() {
		line := scanner.Text()
		// line format: "ssh-ed25519 AAA... candidate X"
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			candidateKey := parts[0] + " " + parts[1]
			if strings.HasPrefix(sshPubKey, candidateKey) {
				found = true
				break
			}
		}
	}
	if !found {
		t.Errorf("Original key not found in output")
	}
}

func TestSshKeyScan(t *testing.T) {
	tempdir := TempDir(t)
	defer os.RemoveAll(tempdir)
	out := path.Join(tempdir, "out")
	in := path.Join(tempdir, "in")

	// Prepare input from keyscan.txt
	keyscanPath := Asset("keyscan.txt")
	content, err := ioutil.ReadFile(keyscanPath)
	ok(t, err)

	var ageKeys []string
	var validSSHKeys []string

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		ageKeyPtr, err := sshage.SSHPublicKeyToAge([]byte(line))
		if err != nil {
			// Expected for non-ed25519 keys
			continue
		}
		ageKeys = append(ageKeys, *ageKeyPtr)
		validSSHKeys = append(validSSHKeys, line)
	}

	err = ioutil.WriteFile(in, []byte(strings.Join(ageKeys, "\n")), 0644)
	ok(t, err)

	err = convertKeys([]string{"age-to-ssh", "-i", in, "-o", out})
	ok(t, err)

	rawOutput, err := ioutil.ReadFile(out)
	ok(t, err)

	// For each valid SSH key, ensure it is found in the output candidates
	outputStr := string(rawOutput)
	fmt.Printf("output:\n%s", outputStr)

	for _, sshKey := range validSSHKeys {
		parts := strings.Fields(sshKey)

		var keyType, keyBlob string
		for i, p := range parts {
			if p == "ssh-ed25519" {
				if i+1 < len(parts) {
					keyType = p
					keyBlob = parts[i+1]
					break
				}
			}
		}

		if keyType == "" || keyBlob == "" {
			continue
		}

		keyPart := keyType + " " + keyBlob

		if !strings.Contains(outputStr, keyPart) {
			t.Errorf("Original key not found in output: %s", keyPart)
		}
	}
}

func TestVersionFlag(t *testing.T) {
	tempdir := TempDir(t)
	defer os.RemoveAll(tempdir)
	out := path.Join(tempdir, "out")

	err := convertKeys([]string{"age-to-ssh", "-version", "-o", out})
	ok(t, err)

	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Errorf("expected no output file, but found one")
	}
}
