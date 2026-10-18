// Package services, logos.go: project and team logos.
//
// An admin uploads a small image; the console shows it in place of the
// initials tile. The service accepts PNG or JPEG only (never SVG, which
// can carry script), at most 64 KiB, 16 to 512 px on each side. It
// decodes the upload with the standard library and re-encodes it as
// PNG, so metadata is dropped and a file that is also something else
// (a polyglot) does not survive. Only the re-encoded PNG is stored.
//
// Audit metadata carries the size, digest and dimensions of the stored
// image, never its bytes.
package services

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"log/slog"
	"mime"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// Logo limits. MaxBytes applies to the upload and to the stored PNG.
const (
	LogoMaxBytes = 64 * 1024
	LogoMinSide  = 16
	LogoMaxSide  = 512
)

// Logo sentinels. The handler maps each to an HTTP status.
var (
	// ErrLogoUnsupportedType: not image/png or image/jpeg (415).
	ErrLogoUnsupportedType = errors.New("services: logo must be a PNG or JPEG image")
	// ErrLogoTooLarge: the upload, or the PNG it converts to, is over 64 KiB (413).
	ErrLogoTooLarge = errors.New("services: logo must be 64 KiB or smaller")
	// ErrLogoUnreadable: the bytes don't decode as the declared type (422).
	ErrLogoUnreadable = errors.New("services: logo could not be read as an image")
	// ErrLogoDimensions: a side is under 16 or over 512 px (422).
	ErrLogoDimensions = errors.New("services: logo must be between 16 and 512 pixels on each side")
	// ErrLogoEntityNotFound: the project or team doesn't exist (404).
	ErrLogoEntityNotFound = errors.New("services: logo owner not found")
)

// LogoService stores and serves project and team logos.
type LogoService struct {
	logos    storage.LogoRepository
	projects storage.ProjectRepository
	teams    storage.TeamRepository
	audit    storage.AuditEventRepository
}

// NewLogoService wires the service. projects and teams are used to
// check the owner exists before a logo is stored.
func NewLogoService(logos storage.LogoRepository, projects storage.ProjectRepository, teams storage.TeamRepository, audit storage.AuditEventRepository) *LogoService {
	return &LogoService{logos: logos, projects: projects, teams: teams, audit: audit}
}

// Put validates, re-encodes and stores a logo, and returns its version.
// actorID is the session identity of the admin uploading it.
func (s *LogoService) Put(ctx context.Context, kind storage.LogoKind, entityID uuid.UUID, contentType string, body []byte, actorID string) (string, error) {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || (mediaType != "image/png" && mediaType != "image/jpeg") {
		return "", ErrLogoUnsupportedType
	}
	if len(body) > LogoMaxBytes {
		return "", ErrLogoTooLarge
	}
	if len(body) == 0 {
		return "", ErrLogoUnreadable
	}

	decodeConfig, decode := png.DecodeConfig, png.Decode
	if mediaType == "image/jpeg" {
		decodeConfig, decode = jpeg.DecodeConfig, jpeg.Decode
	}
	// Read the header first so an oversized image is refused before any
	// pixels are allocated.
	cfg, err := decodeConfig(bytes.NewReader(body))
	if err != nil {
		return "", ErrLogoUnreadable
	}
	if cfg.Width < LogoMinSide || cfg.Height < LogoMinSide || cfg.Width > LogoMaxSide || cfg.Height > LogoMaxSide {
		return "", ErrLogoDimensions
	}
	img, err := decode(bytes.NewReader(body))
	if err != nil {
		return "", ErrLogoUnreadable
	}

	stored, err := encodeLogoPNG(img)
	if err != nil {
		return "", fmt.Errorf("services: encode logo: %w", err)
	}
	if len(stored) > LogoMaxBytes {
		return "", ErrLogoTooLarge
	}

	if err := s.ownerExists(ctx, kind, entityID); err != nil {
		return "", err
	}

	digest := sha256.Sum256(stored)
	bounds := img.Bounds()
	logo := &storage.Logo{
		EntityID:   entityID,
		PNG:        stored,
		ByteLength: len(stored),
		SHA256:     hex.EncodeToString(digest[:]),
		Width:      bounds.Dx(),
		Height:     bounds.Dy(),
		UpdatedBy:  actorID,
	}
	if err := s.logos.Upsert(ctx, kind, logo); err != nil {
		return "", err
	}
	s.emit(ctx, kind, entityID, "updated", actorID, logo)
	return logo.Version(), nil
}

// Delete removes a logo. storage.ErrNotFound when there is none.
func (s *LogoService) Delete(ctx context.Context, kind storage.LogoKind, entityID uuid.UUID, actorID string) error {
	removed, err := s.logos.Delete(ctx, kind, entityID)
	if err != nil {
		return err
	}
	s.emit(ctx, kind, entityID, "removed", actorID, removed)
	return nil
}

// Get returns a stored logo. storage.ErrNotFound when there is none.
func (s *LogoService) Get(ctx context.Context, kind storage.LogoKind, entityID uuid.UUID) (*storage.Logo, error) {
	return s.logos.Get(ctx, kind, entityID)
}

// Versions returns entity id → logo version for the ids that have one.
func (s *LogoService) Versions(ctx context.Context, kind storage.LogoKind, entityIDs []uuid.UUID) (map[uuid.UUID]string, error) {
	return s.logos.Versions(ctx, kind, entityIDs)
}

func (s *LogoService) ownerExists(ctx context.Context, kind storage.LogoKind, entityID uuid.UUID) error {
	var err error
	switch kind {
	case storage.LogoKindProject:
		_, err = s.projects.Get(ctx, entityID)
	case storage.LogoKindTeam:
		_, err = s.teams.Get(ctx, entityID)
	default:
		return storage.ErrUnknownLogoKind
	}
	if errors.Is(err, storage.ErrNotFound) {
		return ErrLogoEntityNotFound
	}
	return err
}

// emit records project.logo.updated and the like. A failed append is
// logged and doesn't undo the write, as for the other tenancy writes.
func (s *LogoService) emit(ctx context.Context, kind storage.LogoKind, entityID uuid.UUID, verb, actorID string, l *storage.Logo) {
	if s.audit == nil {
		return
	}
	action := string(kind) + ".logo." + verb
	evt := &storage.AuditEvent{
		Actor:         auditActor(ctx, actorID),
		Action:        action,
		Resource:      string(kind) + ":" + entityID.String(),
		Status:        storage.AuditStatusSuccess,
		CorrelationID: uuid.New(),
		Metadata: map[string]any{
			"byte_length": l.ByteLength,
			"sha256":      l.SHA256,
			"width":       l.Width,
			"height":      l.Height,
		},
	}
	if err := s.audit.Append(ctx, evt); err != nil {
		slog.WarnContext(ctx, "audit append failed", "action", action, "err", err)
	}
}

// encodeLogoPNG writes img as a PNG with no ancillary chunks: the
// standard encoder emits only the image data, so EXIF, text chunks and
// anything appended to the upload are gone.
func encodeLogoPNG(img image.Image) ([]byte, error) {
	var buf bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.BestCompression}
	if err := enc.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
