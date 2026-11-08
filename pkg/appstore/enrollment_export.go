package appstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const EnrollmentSchema = "ipatool-fairplay-enrollment-v1"

type EnrollmentFile struct {
	Path        string `json:"path"`
	VirtualPath string `json:"virtual_path,omitempty"`
	Bytes       int    `json:"bytes"`
	SHA256      string `json:"sha256"`
}

type EnrollmentLicense struct {
	ID   int64          `json:"id"`
	File EnrollmentFile `json:"file"`
}

// EnrollmentManifest is an export contract for offline consumers. Successful
// native import is not a claim that an IPA has been decrypted or verified.
type EnrollmentManifest struct {
	Schema               string              `json:"schema"`
	AppID                int64               `json:"app_id"`
	BundleID             string              `json:"bundle_id,omitempty"`
	ExternalVersionID    string              `json:"external_version_id"`
	Hardware             EnrollmentFile      `json:"hardware"`
	State                []EnrollmentFile    `json:"state"`
	Licenses             []EnrollmentLicense `json:"licenses"`
	NativeImportComplete bool                `json:"native_import_complete"`
}

func enrollmentStatePath(virtual string) (string, error) {
	for prefix, directory := range map[string]string{
		"/var/db/fpsd/SC Info/": "state/system/", "/Users/Shared/SC Info/": "state/shared/",
	} {
		if strings.HasPrefix(virtual, prefix) {
			name := strings.TrimPrefix(virtual, prefix)
			if name == "SC Info.sidb" || name == "SC Info.sids" {
				return directory + name, nil
			}
		}
	}
	return "", errors.New("unsupported virtual enrollment state path")
}

func validateEnrollmentOutput(out EnrollmentOutput) error {
	if len(out.Hardware) != 6 || out.App.ID <= 0 || out.ExternalVersionID == "" || len(out.Files) == 0 || len(out.Files) > 4 || len(out.Sinfs) == 0 || len(out.Sinfs) > 64 {
		return errors.New("incomplete enrollment export material")
	}
	if len(out.Files["/var/db/fpsd/SC Info/SC Info.sidb"]) < 8 {
		return errors.New("enrollment export requires a server SIDB")
	}
	for virtual, data := range out.Files {
		if _, err := enrollmentStatePath(virtual); err != nil {
			return err
		}
		if len(data) == 0 || len(data) > 16<<20 {
			return errors.New("invalid enrollment state extent")
		}
	}
	seen := make(map[int64]bool)
	for _, license := range out.Sinfs {
		if len(license.Data) == 0 || len(license.Data) > 1<<20 || seen[license.ID] {
			return errors.New("invalid or ambiguous enrollment license")
		}
		seen[license.ID] = true
	}
	return nil
}

// WriteEnrollment creates a new mode-0700 export directory; it never replaces
// existing state. The manifest is written last. An interrupted export without
// manifest.json is incomplete and must not be consumed.
func WriteEnrollment(ctx context.Context, directory string, out EnrollmentOutput) (manifest EnrollmentManifest, err error) {
	if ctx == nil {
		return manifest, errors.New("enrollment export context is required")
	}
	if err := ctx.Err(); err != nil {
		return manifest, err
	}
	if err := validateEnrollmentOutput(out); err != nil {
		return manifest, err
	}
	if !filepath.IsAbs(directory) {
		return manifest, errors.New("enrollment export directory must be absolute")
	}
	if err := os.Mkdir(directory, 0700); err != nil {
		return manifest, fmt.Errorf("create new enrollment export: %w", err)
	}
	write := func(relative string, data []byte) (EnrollmentFile, error) {
		if err := ctx.Err(); err != nil {
			return EnrollmentFile{}, err
		}
		destination := filepath.Join(directory, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
			return EnrollmentFile{}, err
		}
		file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return EnrollmentFile{}, err
		}
		_, writeErr := file.Write(data)
		if writeErr == nil {
			writeErr = file.Sync()
		}
		closeErr := file.Close()
		if err := errors.Join(writeErr, closeErr); err != nil {
			return EnrollmentFile{}, err
		}
		digest := sha256.Sum256(data)
		return EnrollmentFile{Path: relative, Bytes: len(data), SHA256: hex.EncodeToString(digest[:])}, nil
	}
	manifest = EnrollmentManifest{Schema: EnrollmentSchema, AppID: out.App.ID, BundleID: out.App.BundleID, ExternalVersionID: out.ExternalVersionID, NativeImportComplete: true}
	if manifest.Hardware, err = write("hardware.bin", out.Hardware); err != nil {
		return EnrollmentManifest{}, err
	}
	paths := make([]string, 0, len(out.Files))
	for virtual := range out.Files {
		paths = append(paths, virtual)
	}
	sort.Strings(paths)
	for _, virtual := range paths {
		relative, _ := enrollmentStatePath(virtual)
		file, err := write(relative, out.Files[virtual])
		if err != nil {
			return EnrollmentManifest{}, err
		}
		file.VirtualPath = virtual
		manifest.State = append(manifest.State, file)
	}
	for index, license := range out.Sinfs {
		file, err := write(fmt.Sprintf("licenses/%03d.sinf", index), license.Data)
		if err != nil {
			return EnrollmentManifest{}, err
		}
		manifest.Licenses = append(manifest.Licenses, EnrollmentLicense{ID: license.ID, File: file})
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return EnrollmentManifest{}, err
	}
	if _, err := write("manifest.json", append(encoded, '\n')); err != nil {
		return EnrollmentManifest{}, err
	}
	return manifest, nil
}
