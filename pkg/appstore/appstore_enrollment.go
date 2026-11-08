package appstore

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/majd/ipatool/v2/internal/sap/assets"
	"github.com/majd/ipatool/v2/internal/sap/machine"
)

type EnrollmentInput struct {
	Context           context.Context
	Account           Account
	App               App
	ExternalVersionID string
	Progress          func(string)
}

// EnrollmentOutput contains account-bound private material, not a decryption
// key or plaintext IPA. Never log it or publish it as an ordinary download.
type EnrollmentOutput struct {
	Hardware          []byte
	Files             map[string][]byte
	Sinfs             []Sinf
	App               App
	ExternalVersionID string
	NativeProfile     EnrollmentProfile
}

type enrollmentSession interface {
	KBSync() ([]byte, error)
	Import([]byte) (map[string][]byte, error)
	Close() error
}

type enrollmentFactory func(context.Context, []byte, uint64) (enrollmentSession, error)

func defaultEnrollmentFactory(ctx context.Context, hardware []byte, dsid uint64) (enrollmentSession, error) {
	bundle, err := assets.Load(ctx)
	if err != nil {
		return nil, fmt.Errorf("load native enrollment assets: %w", err)
	}
	return machine.OpenEnrollment(ctx, bundle, hardware, dsid)
}

// Enroll keeps a fresh generator alive across exactly one authorization request
// and native keybag import. Cached KBSync, legacy download fallbacks, automatic
// purchase and login retries are deliberately not part of this operation.
func (t *appstore) Enroll(input EnrollmentInput) (out EnrollmentOutput, returnErr error) {
	if input.Context == nil {
		return out, errors.New("enrollment context is required")
	}
	if input.App.ID <= 0 {
		return out, errors.New("enrollment requires a positive app ID")
	}
	dsid, err := strconv.ParseUint(input.Account.DirectoryServicesID, 10, 64)
	if err != nil || dsid == 0 || input.Account.PasswordToken == "" {
		return out, errors.New("enrollment requires a saved authenticated account")
	}
	if input.ExternalVersionID == "" {
		return out, errors.New("enrollment requires an explicit external version ID")
	}
	if version, err := strconv.ParseUint(input.ExternalVersionID, 10, 64); err != nil || version == 0 {
		return out, errors.New("invalid enrollment external version ID")
	}
	ctx, cancel := context.WithTimeout(input.Context, 5*time.Minute)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if t.enrollmentFactory == nil || t.machine == nil {
		return out, errors.New("native enrollment is not configured")
	}
	progress := func(stage string) {
		if input.Progress != nil {
			input.Progress(stage)
		}
	}
	address, err := t.machine.MacAddress()
	if err != nil {
		return out, err
	}
	guid, hardware, err := machineIdentity(address)
	if err != nil {
		return out, err
	}
	progress("resolving authorization endpoint")
	bag, err := t.fetchURLBagContext(ctx, guid)
	if err != nil {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		return out, errors.New("could not resolve enrollment authorization endpoint")
	}
	endpoint, err := newDownloadEndpoint(bag.EntDownloadEndpoint, entDownloadPath)
	if err != nil {
		return out, err
	}
	progress("opening native enrollment session")
	session, err := t.enrollmentFactory(ctx, hardware, dsid)
	if err != nil {
		return out, err
	}
	defer func() {
		returnErr = errors.Join(returnErr, session.Close())
		if returnErr != nil {
			clear(out.Hardware)
			for _, data := range out.Files {
				clear(data)
			}
			for _, license := range out.Sinfs {
				clear(license.Data)
			}
			out = EnrollmentOutput{}
		}
	}()
	progress("generating fresh KBSync")
	blob, err := session.KBSync()
	if err != nil {
		return out, err
	}
	defer clear(blob)
	if len(blob) == 0 {
		return out, errors.New("native enrollment generated an empty KBSync")
	}
	progress("authorizing app download")
	response, err := t.sendEntDownloadRequest(ctx, endpoint, input.Account, input.App, guid, input.ExternalVersionID, hardware, base64.StdEncoding.EncodeToString(blob))
	defer clear(response.Data.Keybag)
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	switch response.Data.FailureType {
	case FailureTypePasswordTokenExpired, FailureTypeSignInRequired, FailureTypeDeviceVerificationFailed:
		return out, ErrPasswordTokenExpired
	case FailureTypeLicenseNotFound:
		return out, ErrLicenseRequired
	}
	if err != nil {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		// Do not attach HTTP result metadata, cookies or license payloads to a
		// diagnostic error. Callers can reauthenticate explicitly when necessary.
		if errors.Is(err, ErrPasswordTokenExpired) || errors.Is(err, ErrLicenseRequired) {
			return out, err
		}
		return out, errors.New("enrollment authorization failed; verify the account, app license, version and network")
	}
	if len(response.Data.Keybag) < 8 || len(response.Data.Keybag) > 1<<20 || len(response.Data.Items) != 1 || len(response.Data.Items[0].Sinfs) == 0 {
		return out, errors.New("authorization returned no unambiguous enrollment material")
	}
	progress("importing keybag in the original native session")
	files, err := session.Import(response.Data.Keybag)
	if err != nil {
		return out, err
	}
	if len(files) == 0 {
		return out, errors.New("native enrollment created no state files")
	}
	app := input.App
	app.BundleID, _ = response.Data.Items[0].Metadata["softwareVersionBundleId"].(string)
	product, build := assets.Version()
	out = EnrollmentOutput{Hardware: bytes.Clone(hardware), Files: files, Sinfs: response.Data.Items[0].Sinfs, App: app, ExternalVersionID: input.ExternalVersionID,
		NativeProfile: EnrollmentProfile{ProductVersion: product, BuildVersion: build}}
	if err := validateEnrollmentOutput(out); err != nil {
		return out, err
	}
	progress("native enrollment completed")
	return out, nil
}
