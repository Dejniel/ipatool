package cmd

import (
	"crypto/sha256"
	"fmt"
	stdos "os"
	"path/filepath"
	"strings"

	"github.com/majd/ipatool/v2/pkg/util/operatingsystem"
)

func resolveStateDirectory(os operatingsystem.OperatingSystem, home, explicit string) (string, error) {
	if explicit == "" {
		return prepareStateDirectory(os, home)
	}
	if !filepath.IsAbs(explicit) {
		return "", fmt.Errorf("--state-directory must be absolute")
	}
	path := filepath.Clean(explicit)
	info, err := stdos.Lstat(path)
	if stdos.IsNotExist(err) {
		if err := stdos.MkdirAll(path, 0700); err != nil {
			return "", fmt.Errorf("create private profile: %w", err)
		}
		info, err = stdos.Lstat(path)
	}
	if err != nil {
		return "", fmt.Errorf("inspect private profile: %w", err)
	}
	if !info.IsDir() || info.Mode()&stdos.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return "", fmt.Errorf("--state-directory must be a private directory (mode 0700), not a symlink: %s", path)
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolve private profile: %w", err)
	}
	return canonical, nil
}

func keychainNamespace(stateDirectory string) string {
	if stateDirectoryOverride == "" {
		return KeychainServiceName
	}
	return fmt.Sprintf("%s/profile/%x", KeychainServiceName, sha256.Sum256([]byte(stateDirectory)))
}

// prepareStateDirectory resolves and migrates session storage before it is opened.
func prepareStateDirectory(os operatingsystem.OperatingSystem, homeDirectory string) (string, error) {
	legacyDirectory := filepath.Join(homeDirectory, ConfigDirectoryName)
	stateDirectory := legacyDirectory

	for _, variable := range []string{"XDG_STATE_HOME", "XDG_DATA_HOME"} {
		if base := os.Getenv(variable); filepath.IsAbs(base) {
			stateDirectory = filepath.Join(base, "ipatool")

			break
		}
	}

	info, err := os.Stat(legacyDirectory)
	if err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("could not read legacy state directory metadata: %w", err)
	}

	if err == nil {
		if !info.IsDir() {
			return "", fmt.Errorf("legacy state path is not a directory: %s", legacyDirectory)
		}
		// Never merge sessions or move a directory into itself. Keeping the legacy
		// directory also preserves authentication when migration is unavailable.
		relative, err := filepath.Rel(legacyDirectory, stateDirectory)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return legacyDirectory, nil
		}

		if _, err := os.Stat(stateDirectory); err == nil || !os.IsNotExist(err) {
			return legacyDirectory, nil
		}

		if err := os.MkdirAll(filepath.Dir(stateDirectory), 0700); err != nil {
			return legacyDirectory, nil
		}
		// Rename keeps cookies and encrypted credentials together, with their
		// existing permissions. Cross-filesystem moves fall back to legacy storage.
		if err := os.Rename(legacyDirectory, stateDirectory); err != nil {
			return legacyDirectory, nil
		}

		return stateDirectory, nil
	}

	if err := os.MkdirAll(stateDirectory, 0700); err != nil {
		return "", fmt.Errorf("failed to create state directory: %w", err)
	}

	return stateDirectory, nil
}
