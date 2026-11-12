package collect

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// Blob layout:
//
//	magic "SCA1" | keyID (1) | nonce (12) | ciphertext+tag
//
// The key ID travels with the ciphertext, so a rotated keyset reads what the
// previous key wrote without a separate index and without a window in which
// writes and reads disagree.
const (
	blobMagic  = "SCA1"
	blobHeader = 4 + 1 + 12
)

var (
	ErrMalformedBlob = errors.New("collect: malformed blob")
	ErrUnknownKeyID  = errors.New("collect: unknown key id")
	ErrKeyInUse      = errors.New("collect: key still referenced by stored rows")
)

// KeySet holds one active key and any number of retired keys. The active key
// seals; every held key opens. Raw material is retained alongside the AEAD so
// a key can be removed and the keyset re-serialised without asking the
// operator for the secret again.
type KeySet struct {
	active byte
	raw    map[byte][]byte
	aead   map[byte]cipher.AEAD
}

func NewKeySet(active byte, keys map[byte][]byte) (*KeySet, error) {
	if len(keys) == 0 {
		return nil, errors.New("collect: keyset is empty")
	}
	raw := make(map[byte][]byte, len(keys))
	built := make(map[byte]cipher.AEAD, len(keys))
	for id, material := range keys {
		if len(material) != 32 {
			return nil, fmt.Errorf("collect: key %d must be 32 bytes, got %d", id, len(material))
		}
		block, err := aes.NewCipher(material)
		if err != nil {
			return nil, fmt.Errorf("collect: key %d: %w", id, err)
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("collect: key %d: %w", id, err)
		}
		raw[id] = append([]byte(nil), material...)
		built[id] = gcm
	}
	if _, ok := built[active]; !ok {
		return nil, fmt.Errorf("collect: active key id %d is not in the keyset", active)
	}
	return &KeySet{active: active, raw: raw, aead: built}, nil
}

// ParseKeySet reads "1:<base64>,2:<base64>" plus the active id. Development
// only: the production path is LoadKeyFile.
func ParseKeySet(spec string, active byte) (*KeySet, error) {
	keys := make(map[byte][]byte)
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		idStr, b64, ok := strings.Cut(part, ":")
		if !ok {
			return nil, errors.New("collect: keyset entry must be id:base64")
		}
		id64, err := strconv.ParseUint(strings.TrimSpace(idStr), 10, 8)
		if err != nil || id64 == 0 || id64 > 255 {
			return nil, fmt.Errorf("collect: bad key id %q", idStr)
		}
		material, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
		if err != nil {
			return nil, fmt.Errorf("collect: key %d is not base64", id64)
		}
		keys[byte(id64)] = material
	}
	return NewKeySet(active, keys)
}

// keyFile is the on-disk format of SIREN_KEY_FILE.
type keyFile struct {
	Active byte              `json:"active"`
	Keys   map[string]string `json:"keys"`
}

// LoadKeyFile reads the keyset from a file. The permission check refuses any
// file that is group- or world-writable: a writable key file can be replaced
// by another process, which is equivalent to key compromise.
//
// Read access by group or others is permitted so that Docker secrets
// (mounted as root:root 0444) can be used without running the container as
// root. World-readable key material is an acceptable tradeoff when the host
// filesystem and container isolation are trusted; tighten to 0o400 if the
// deployment mounts the secret with explicit UID ownership.
//
// The permission check is skipped on Windows, where the mode bits do not
// carry meaningful POSIX ACLs.
func LoadKeyFile(path string) (*KeySet, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("collect: key file: %w", err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("collect: key path %s is a directory", path)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("collect: key file %s is group/world writable (%04o); chmod 0444 or stricter", path, info.Mode().Perm())
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("collect: key file: %w", err)
	}
	var kf keyFile
	if err := json.Unmarshal(raw, &kf); err != nil {
		return nil, fmt.Errorf("collect: key file: %w", err)
	}
	if len(kf.Keys) == 0 {
		return nil, errors.New("collect: key file has no keys")
	}

	keys := make(map[byte][]byte, len(kf.Keys))
	for idStr, b64 := range kf.Keys {
		ids, err := strconv.ParseUint(idStr, 10, 8)
		if err != nil || ids == 0 || ids > 255 {
			return nil, fmt.Errorf("collect: key file: bad key id %q", idStr)
		}
		material, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("collect: key file: key %d is not base64", ids)
		}
		keys[byte(ids)] = material
	}
	return NewKeySet(kf.Active, keys)
}

// SaveKeyFile writes the keyset atomically with 0600. Used by the retire
// command once the store confirms no row still carries the key.
func SaveKeyFile(path string, ks *KeySet) error {
	blob, err := ks.MarshalFile()
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".siren-keys-*")
	if err != nil {
		return fmt.Errorf("collect: key file: %w", err)
	}
	name := tmp.Name()
	defer os.Remove(name)

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("collect: key file: %w", err)
	}
	if _, err := tmp.Write(blob); err != nil {
		tmp.Close()
		return fmt.Errorf("collect: key file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("collect: key file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("collect: key file: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("collect: key file: %w", err)
	}
	return nil
}

// MarshalFile renders the keyset in the SIREN_KEY_FILE format.
func (k *KeySet) MarshalFile() ([]byte, error) {
	kf := keyFile{Active: k.active, Keys: make(map[string]string, len(k.raw))}
	for id, material := range k.raw {
		kf.Keys[strconv.Itoa(int(id))] = base64.StdEncoding.EncodeToString(material)
	}
	return json.MarshalIndent(kf, "", "  ")
}

// Without returns a copy of the keyset with one key removed. The active key
// cannot be retired, and an unknown id is an error rather than a no-op so a
// typo does not look like success.
func (k *KeySet) Without(id byte) (*KeySet, error) {
	if id == k.active {
		return nil, errors.New("collect: cannot retire the active key")
	}
	if _, ok := k.raw[id]; !ok {
		return nil, fmt.Errorf("%w: %d", ErrUnknownKeyID, id)
	}
	keys := make(map[byte][]byte, len(k.raw)-1)
	for kid, material := range k.raw {
		if kid == id {
			continue
		}
		keys[kid] = material
	}
	return NewKeySet(k.active, keys)
}

func (k *KeySet) IDs() []byte {
	ids := make([]byte, 0, len(k.raw))
	for id := range k.raw {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

func (k *KeySet) Active() byte { return k.active }

func (k *KeySet) Seal(aad, plain []byte) ([]byte, error) {
	gcm, ok := k.aead[k.active]
	if !ok {
		return nil, ErrUnknownKeyID
	}
	out := make([]byte, blobHeader, blobHeader+len(plain)+gcm.Overhead())
	copy(out, blobMagic)
	out[4] = k.active
	if _, err := rand.Read(out[5:blobHeader]); err != nil {
		return nil, err
	}
	return gcm.Seal(out[:blobHeader], out[5:blobHeader], plain, aad), nil
}

func (k *KeySet) Open(aad, blob []byte) ([]byte, error) {
	if len(blob) < blobHeader || string(blob[:4]) != blobMagic {
		return nil, ErrMalformedBlob
	}
	gcm, ok := k.aead[blob[4]]
	if !ok {
		return nil, fmt.Errorf("%w: %d", ErrUnknownKeyID, blob[4])
	}
	plain, err := gcm.Open(nil, blob[5:blobHeader], blob[blobHeader:], aad)
	if err != nil {
		return nil, fmt.Errorf("collect: decrypt: %w", err)
	}
	return plain, nil
}
