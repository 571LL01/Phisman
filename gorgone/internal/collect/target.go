package collect

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// ValidateTarget constrains what a campaign can redirect to. A {{.Target}}
// that reaches a redirect sink is an open redirect; scheme filtering is the
// only place that is cheap to enforce.
//
// A root-relative path is accepted as an in-app target, but only with exactly
// one leading slash: //host and /\host are authority-relative in browsers and
// would leave this deployment.
func ValidateTarget(raw string, allowHTTP bool) (string, error) {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "/") {
		return validateInternalTarget(raw)
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("collect: target: %w", err)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !allowHTTP {
			return "", errors.New("collect: target must be https")
		}
	default:
		return "", fmt.Errorf("collect: target scheme %q not allowed", u.Scheme)
	}
	if u.Host == "" {
		return "", errors.New("collect: target has no host")
	}
	if u.User != nil {
		return "", errors.New("collect: target must not embed credentials")
	}
	return u.String(), nil
}

// validateInternalTarget accepts exactly one leading slash and rejects every
// form a browser or proxy could reinterpret as an authority: //host, /\host,
// and encoded variants that decode to either. Dot segments are refused too,
// because /..//host normalizes to //host in some clients.
func validateInternalTarget(raw string) (string, error) {
	if strings.HasPrefix(raw, "//") {
		return "", errors.New("collect: target must not be protocol-relative")
	}
	if strings.Contains(raw, `\`) {
		return "", errors.New("collect: target must not contain a backslash")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("collect: target: %w", err)
	}
	if u.Scheme != "" || u.Host != "" || u.User != nil {
		return "", errors.New("collect: target is not a root-relative path")
	}
	if u.Path == "" || u.Path[0] != '/' {
		return "", errors.New("collect: target is not a root-relative path")
	}
	// url.Parse decodes the path, so %2f and %5c are visible here even when
	// the raw form looked harmless.
	if strings.HasPrefix(u.Path, "//") || strings.Contains(u.Path, `\`) {
		return "", errors.New("collect: target is not a safe root-relative path")
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == "." || seg == ".." {
			return "", errors.New("collect: target must not contain dot segments")
		}
	}
	return u.String(), nil
}

// isInternalTarget reports whether a validated target is an in-app path. It is
// called after ValidateTarget, so the // case is already impossible.
func isInternalTarget(target string) bool {
	return strings.HasPrefix(target, "/") && !strings.HasPrefix(target, "//")
}

// GuardKeyLocation refuses to start when the key material sits next to the
// data it protects. A key in the same directory as the .db is not a second
// factor against disk exfiltration, it is the same factor twice. Both sides
// are resolved through symlinks first: a link pointing into the data
// directory is the same failure as a copy in it.
func GuardKeyLocation(keyPath, dataDir string) error {
	if keyPath == "" {
		return nil // key supplied by environment or an agent; nothing to check
	}
	absKey, err := resolvePath(keyPath)
	if err != nil {
		return err
	}
	absData, err := resolvePath(dataDir)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(absData, absKey)
	if err != nil {
		return err
	}
	if rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("collect: key file %q resolves inside data dir %q", absKey, absData)
	}
	return nil
}

// resolvePath expands symlinks in the longest existing prefix of p. The leaf
// may not exist yet (the key file is often created after first boot), so the
// deepest existing component is resolved and the missing remainder is
// re-appended unchanged. A dangling symlink is an error, not a missing leaf:
// treating it as an ordinary name would let a link into the data directory
// through on the next boot, once its target exists.
func resolvePath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	cur := abs
	rest := ""
	for {
		fi, statErr := os.Lstat(cur)
		switch {
		case statErr == nil:
			if fi.Mode()&os.ModeSymlink != 0 {
				resolved, err := filepath.EvalSymlinks(cur)
				if err != nil {
					return "", fmt.Errorf("collect: resolve symlink %s: %w", cur, err)
				}
				return filepath.Join(resolved, rest), nil
			}
			resolved, err := filepath.EvalSymlinks(cur)
			if err != nil {
				return "", fmt.Errorf("collect: resolve %s: %w", cur, err)
			}
			return filepath.Join(resolved, rest), nil
		case !os.IsNotExist(statErr):
			return "", fmt.Errorf("collect: stat %s: %w", cur, statErr)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return abs, nil
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}
