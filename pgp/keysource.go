/*
Package pgp contains an implementation of the go.mozilla.org/sops/v3.MasterKey interface that encrypts and decrypts the
data key by first trying with the golang.org/x/crypto/openpgp package and if that fails, by calling the "gpg" binary.
*/
package pgp //import "go.mozilla.org/sops/v3/pgp"

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/user"
	"path"
	"strings"
	"sync"
	"time"

	"os/exec"

	"github.com/howeyc/gopass"
	"github.com/sirupsen/logrus"
	gpgagent "go.mozilla.org/gopgagent"
	"go.mozilla.org/sops/v3/logging"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

var log *logrus.Logger
var sharedKeyRingPair KeyRingPair

func init() {
	log = logging.NewLogger("PGP")
}

// MasterKey is a PGP key used to securely store sops' data key by encrypting it and decrypting it
type MasterKey struct {
	Fingerprint  string
	EncryptedKey string
	CreationDate time.Time
	KeyRingPair  *KeyRingPair
}

// KeyRingPair holds a public and a secret keyring, cached across calls so that we don't load N thousand keys repeatedly
type KeyRingPair struct {
	Secret KeyRing
	Public KeyRing
}

// KeyRing is a list of loaded keys, with some safey state
type KeyRing struct {
	sync.RWMutex
	List openpgp.EntityList
	Done bool
	Err  error
}

// EncryptedDataKey returns the encrypted data key this master key holds
func (key *MasterKey) EncryptedDataKey() []byte {
	return []byte(key.EncryptedKey)
}

// SetEncryptedDataKey sets the encrypted data key for this master key
func (key *MasterKey) SetEncryptedDataKey(enc []byte) {
	key.EncryptedKey = string(enc)
}

func gpgBinary() string {
	binary := "gpg"
	if envBinary := os.Getenv("SOPS_GPG_EXEC"); envBinary != "" {
		binary = envBinary
	}
	return binary
}

func (key *MasterKey) encryptWithGPGBinary(dataKey []byte) error {
	fingerprint := key.Fingerprint
	if offset := len(fingerprint) - 16; offset > 0 {
		fingerprint = fingerprint[offset:]
	}
	args := []string{
		"--no-default-recipient",
		"--yes",
		"--encrypt",
		"-a",
		"-r",
		key.Fingerprint,
		"--trusted-key",
		fingerprint,
		"--no-encrypt-to",
	}
	cmd := exec.Command(gpgBinary(), args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdin = bytes.NewReader(dataKey)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return err
	}
	key.EncryptedKey = stdout.String()
	return nil
}

func getKeyFromKeyServer(fingerprint string) (openpgp.Entity, error) {
	log.WithField("missing-fp", fingerprint).Warn("Deprecation Warning: GPG key fetching from a keyserver within sops will be removed in a future version of sops. See https://github.com/mozilla/sops/issues/727 for more information.")

	url := fmt.Sprintf("https://keys.openpgp.org/vks/v1/by-fingerprint/%s", fingerprint)
	resp, err := http.Get(url)
	if err != nil {
		return openpgp.Entity{}, fmt.Errorf("error getting key from keyserver: %s", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return openpgp.Entity{}, fmt.Errorf("keyserver returned non-200 status code %s", resp.Status)
	}
	ents, err := openpgp.ReadArmoredKeyRing(resp.Body)
	if err != nil {
		return openpgp.Entity{}, fmt.Errorf("could not read entities: %s", err)
	}
	return *ents[0], nil
}

func (key *MasterKey) getPubKey() (openpgp.Entity, error) {
	ring, err := key.KeyRingPair.pubRing()
	if err == nil {
		fingerprints := key.fingerprintMap(ring)
		entity, ok := fingerprints[key.Fingerprint]
		if ok {
			return entity, nil
		}
	} else {
		log.WithError(err).Debug("failed to find public ring")
	}
	// Beware that returning errors here will probably be masked by GPG fallback.
	entity, err := getKeyFromKeyServer(key.Fingerprint)
	if err != nil {
		return openpgp.Entity{},
			fmt.Errorf("key with fingerprint %s is not available "+
				"in keyring and could not be retrieved from keyserver", key.Fingerprint)
	}
	return entity, nil
}

func (key *MasterKey) encryptWithCryptoOpenPGP(dataKey []byte) error {
	entity, err := key.getPubKey()
	if err != nil {
		return err
	}
	encbuf := new(bytes.Buffer)
	armorbuf, err := armor.Encode(encbuf, "PGP MESSAGE", nil)
	if err != nil {
		return err
	}
	plaintextbuf, err := openpgp.Encrypt(armorbuf, []*openpgp.Entity{&entity}, nil, &openpgp.FileHints{IsBinary: true}, nil)
	if err != nil {
		return err
	}
	_, err = plaintextbuf.Write(dataKey)
	if err != nil {
		return err
	}
	err = plaintextbuf.Close()
	if err != nil {
		return err
	}
	err = armorbuf.Close()
	if err != nil {
		return err
	}
	bytes, err := ioutil.ReadAll(encbuf)
	if err != nil {
		return err
	}
	key.EncryptedKey = string(bytes)
	return nil
}

// Encrypt encrypts the data key with the PGP key with the same fingerprint as the MasterKey.
// It looks for PGP public keys in $GNUPGHOME/pubring.gpg.
// WARNING: this is a deprecated-by-GnuPG historical keyring location and we do not support
// using pubring.kbx.
func (key *MasterKey) Encrypt(dataKey []byte) error {
	openpgpErr := key.encryptWithCryptoOpenPGP(dataKey)
	if openpgpErr == nil {
		log.WithField("fingerprint", key.Fingerprint).Info("Encryption succeeded")
		return nil
	}
	binaryErr := key.encryptWithGPGBinary(dataKey)
	if binaryErr == nil {
		log.WithField("fingerprint", key.Fingerprint).Info("Encryption succeeded")
		return nil
	}
	log.WithField("fingerprint", key.Fingerprint).Info("Encryption failed")
	return fmt.Errorf(
		`could not encrypt data key with PGP key: golang.org/x/crypto/openpgp error: %v; GPG binary error: %v`,
		openpgpErr, binaryErr)
}

// EncryptIfNeeded encrypts the data key with PGP only if it's needed, that is, if it hasn't been encrypted already
func (key *MasterKey) EncryptIfNeeded(dataKey []byte) error {
	if key.EncryptedKey == "" {
		return key.Encrypt(dataKey)
	}
	return nil
}

func (key *MasterKey) decryptWithGPGBinary() ([]byte, error) {
	args := []string{
		"--use-agent",
		"-d",
	}
	cmd := exec.Command(gpgBinary(), args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdin = strings.NewReader(key.EncryptedKey)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return nil, err
	}
	return stdout.Bytes(), nil
}

func (key *MasterKey) decryptWithCryptoOpenpgp() ([]byte, error) {
	ring, err := key.KeyRingPair.secRing()
	if err != nil {
		return nil, fmt.Errorf("Could not load secring: %s", err)
	}
	block, err := armor.Decode(strings.NewReader(key.EncryptedKey))
	if err != nil {
		return nil, fmt.Errorf("Armor decoding failed: %s", err)
	}
	md, err := openpgp.ReadMessage(block.Body, ring, key.passphrasePrompt(), nil)
	if err != nil {
		return nil, fmt.Errorf("Reading PGP message failed: %s", err)
	}
	if b, err := ioutil.ReadAll(md.UnverifiedBody); err == nil {
		return b, nil
	}
	return nil, fmt.Errorf("The key could not be decrypted with any of the PGP entries")
}

// Decrypt uses PGP to obtain the data key from the EncryptedKey store in the MasterKey and returns it
func (key *MasterKey) Decrypt() ([]byte, error) {
	dataKey, openpgpErr := key.decryptWithCryptoOpenpgp()
	if openpgpErr == nil {
		log.WithField("fingerprint", key.Fingerprint).Info("Decryption succeeded")
		return dataKey, nil
	}
	dataKey, binaryErr := key.decryptWithGPGBinary()
	if binaryErr == nil {
		log.WithField("fingerprint", key.Fingerprint).Info("Decryption succeeded")
		return dataKey, nil
	}
	log.WithField("fingerprint", key.Fingerprint).Info("Decryption failed")
	return nil, fmt.Errorf(
		`could not decrypt data key with PGP key: golang.org/x/crypto/openpgp error: %v; GPG binary error: %v`,
		openpgpErr, binaryErr)
}

// NeedsRotation returns whether the data key needs to be rotated or not
func (key *MasterKey) NeedsRotation() bool {
	return time.Since(key.CreationDate).Hours() > 24*30*6
}

// ToString returns the string representation of the key, i.e. its fingerprint
func (key *MasterKey) ToString() string {
	return key.Fingerprint
}

// NewMasterKeyFromFingerprint takes a PGP fingerprint and returns a new MasterKey with that fingerprint
func NewMasterKeyFromFingerprint(fingerprint string) *MasterKey {
	return &MasterKey{
		Fingerprint:  strings.Replace(fingerprint, " ", "", -1),
		CreationDate: time.Now().UTC(),
		KeyRingPair:  &sharedKeyRingPair,
	}
}

// MasterKeysFromFingerprintString takes a comma separated list of PGP fingerprints and returns a slice of new MasterKeys with those fingerprints
func MasterKeysFromFingerprintString(fingerprint string) []*MasterKey {
	var keys []*MasterKey
	if fingerprint == "" {
		return keys
	}
	for _, s := range strings.Split(fingerprint, ",") {
		keys = append(keys, NewMasterKeyFromFingerprint(s))
	}
	return keys
}

func (krpair *KeyRingPair) secRing() (openpgp.EntityList, error) {
	return krpair.Secret.Loaded(krpair.gpgHome() + "/secring.gpg")
}

func (krpair *KeyRingPair) pubRing() (openpgp.EntityList, error) {
	return krpair.Public.Loaded(krpair.gpgHome() + "/pubring.gpg")
}

func (krpair *KeyRingPair) gpgHome() string {
	dir := os.Getenv("GNUPGHOME")
	if dir == "" {
		usr, err := user.Current()
		if err != nil {
			return path.Join(os.Getenv("HOME"), "/.gnupg")
		}
		return path.Join(usr.HomeDir, ".gnupg")
	}
	return dir
}

func (kring *KeyRing) loadRing(path string) (openpgp.EntityList, error) {
	f, err := os.Open(path)
	if err != nil {
		return openpgp.EntityList{}, err
	}
	defer f.Close()
	keyring, err := openpgp.ReadKeyRing(f)
	if err != nil {
		return keyring, err
	}
	log.WithField("file", path).WithField("key-count", len(keyring)).Debug("loaded public keyring")
	return keyring, nil
}

func (kring *KeyRing) Loaded(path string) (openpgp.EntityList, error) {
	kring.RLock()
	if kring.Done {
		el, err := kring.List, kring.Err
		kring.RUnlock()
		return el, err
	}
	kring.RUnlock()
	kring.Lock()
	defer kring.Unlock()
	if kring.Done {
		return kring.List, kring.Err
	}
	kring.List, kring.Err = kring.loadRing(path)
	kring.Done = true
	return kring.List, kring.Err
}

func (key *MasterKey) fingerprintMap(ring openpgp.EntityList) map[string]openpgp.Entity {
	fps := make(map[string]openpgp.Entity, len(ring))
	for _, entity := range ring {
		if entity != nil {
			fp := strings.ToUpper(hex.EncodeToString(entity.PrimaryKey.Fingerprint[:]))
			fps[fp] = *entity
		}
	}
	return fps
}

func (key *MasterKey) passphrasePrompt() func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
	callCounter := 0
	maxCalls := 3
	return func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		if callCounter >= maxCalls {
			return nil, fmt.Errorf("function passphrasePrompt called too many times")
		}
		callCounter++

		conn, err := gpgagent.NewConn()
		if err == gpgagent.ErrNoAgent {
			log.Infof("gpg-agent not found, continuing with manual passphrase " +
				"input...")
			fmt.Print("Enter PGP key passphrase: ")
			pass, err := gopass.GetPasswd()
			if err != nil {
				return nil, err
			}
			for _, k := range keys {
				k.PrivateKey.Decrypt(pass)
			}
			return pass, err
		}
		if err != nil {
			return nil, fmt.Errorf("Could not establish connection with gpg-agent: %s", err)
		}
		defer conn.Close()
		for _, k := range keys {
			req := gpgagent.PassphraseRequest{
				CacheKey: k.PublicKey.KeyIdShortString(),
				Prompt:   "Passphrase",
				Desc:     fmt.Sprintf("Unlock key %s to decrypt sops's key", k.PublicKey.KeyIdShortString()),
			}
			pass, err := conn.GetPassphrase(&req)
			if err != nil {
				return nil, fmt.Errorf("gpg-agent passphrase request errored: %s", err)
			}
			k.PrivateKey.Decrypt([]byte(pass))
			return []byte(pass), nil
		}
		return nil, fmt.Errorf("No key to unlock")
	}
}

// ToMap converts the MasterKey into a map for serialization purposes
func (key MasterKey) ToMap() map[string]interface{} {
	out := make(map[string]interface{})
	out["fp"] = key.Fingerprint
	out["created_at"] = key.CreationDate.UTC().Format(time.RFC3339)
	out["enc"] = key.EncryptedKey
	return out
}
