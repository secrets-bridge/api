// Package services, logos.go: project and team logos.
//
// An admin uploads a small image; the console shows it in place of the
// initials tile. The service accepts PNG or JPEG only (never SVG, which
// can carry script), at most 64 KiB, 16 to 512 px on each side. It
// decodes the upload with the standard library and re-encodes it as an
// 8-bit PNG of at most 128 px on the longer side, so metadata is dropped
// and a file that is also something else (a polyglot) does not survive.
// Only the re-encoded PNG is stored.
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
	"image/draw"
	"image/jpeg"
	"image/png"
	"log/slog"
	"math"
	"mime"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// Logo limits. MaxBytes applies to the upload and to the stored PNG.
// MinSide and MaxSide bound the upload; StoredSide bounds the longer side
// of the stored image, which is the size the console uploads and more
// than any place it draws a logo needs.
const (
	LogoMaxBytes   = 64 * 1024
	LogoMinSide    = 16
	LogoMaxSide    = 512
	LogoStoredSide = 128
)

// logoFallbackSides are the smaller sizes tried, in order, when the PNG
// at LogoStoredSide is still over LogoMaxBytes. Only noisy images with
// transparency get there: an opaque 128 px image is at most 48 KiB of
// pixel data. 64 px is at most 16 KiB with alpha, so the last step
// always fits.
var logoFallbackSides = []int{96, 64}

// Logo sentinels. The handler maps each to an HTTP status.
var (
	// ErrLogoUnsupportedType: not image/png or image/jpeg (415).
	ErrLogoUnsupportedType = errors.New("services: logo must be a PNG or JPEG image")
	// ErrLogoTooLarge: the upload is over 64 KiB (413).
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
	// Check the owner before decoding, so an upload for a project or team
	// that doesn't exist costs a lookup and not a decode and encode.
	if err := s.ownerExists(ctx, kind, entityID); err != nil {
		return "", err
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

	stored, bounds, err := encodeLogo(img)
	if err != nil {
		return "", fmt.Errorf("services: encode logo: %w", err)
	}

	digest := sha256.Sum256(stored)
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
		// The owner was deleted between the check above and the write.
		if errors.Is(err, storage.ErrNotFound) {
			return "", ErrLogoEntityNotFound
		}
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

// encodeLogo converts img to 8-bit RGBA at most LogoStoredSide px on
// the longer side and encodes it as PNG. Converting first matters for
// JPEG: the standard encoder writes a decoded JPEG (YCbCr) as 16-bit
// RGB, about twice the size. If the result is still over LogoMaxBytes
// it steps down through logoFallbackSides. It returns the PNG and the
// stored image's bounds.
func encodeLogo(img image.Image) ([]byte, image.Rectangle, error) {
	src := toRGBA(img)
	for _, side := range append([]int{LogoStoredSide}, logoFallbackSides...) {
		out := fitWithin(src, side)
		b, err := encodeLogoPNG(out)
		if err != nil {
			return nil, image.Rectangle{}, err
		}
		if len(b) <= LogoMaxBytes {
			return b, out.Bounds(), nil
		}
	}
	// Unreachable for a decodable image: see logoFallbackSides.
	return nil, image.Rectangle{}, errors.New("stored image still over the size limit")
}

// toRGBA copies img into an 8-bit, alpha-premultiplied RGBA image at the
// origin, whatever its source model (YCbCr, CMYK, 16-bit, paletted).
func toRGBA(img image.Image) *image.RGBA {
	b := img.Bounds()
	out := image.NewRGBA(image.Rect(0, 0, b.Dx(), b.Dy()))
	draw.Draw(out, out.Bounds(), img, b.Min, draw.Src)
	return out
}

// fitWithin returns src scaled down so its longer side is at most side
// px, keeping the aspect ratio, or src itself when it already fits.
func fitWithin(src *image.RGBA, side int) *image.RGBA {
	w, h := src.Bounds().Dx(), src.Bounds().Dy()
	if w <= side && h <= side {
		return src
	}
	scale := float64(side) / float64(max(w, h))
	return scaleDown(src,
		max(1, int(math.Round(float64(w)*scale))),
		max(1, int(math.Round(float64(h)*scale))))
}

// scaleDown resizes src (at the origin) to w×h, w and h no larger than
// src, with a box filter: each output pixel is the area-weighted mean
// of the source pixels it covers. Averaging premultiplied values keeps
// transparent edges from darkening.
func scaleDown(src *image.RGBA, w, h int) *image.RGBA {
	sw, sh := src.Bounds().Dx(), src.Bounds().Dy()
	dst := image.NewRGBA(image.Rect(0, 0, w, h))
	fx, fy := float64(sw)/float64(w), float64(sh)/float64(h)
	area := fx * fy
	for dy := range h {
		y0, y1 := float64(dy)*fy, float64(dy+1)*fy
		for dx := range w {
			x0, x1 := float64(dx)*fx, float64(dx+1)*fx
			var sum [4]float64
			for sy := int(y0); sy < sh && float64(sy) < y1; sy++ {
				wy := math.Min(y1, float64(sy+1)) - math.Max(y0, float64(sy))
				for sx := int(x0); sx < sw && float64(sx) < x1; sx++ {
					wt := wy * (math.Min(x1, float64(sx+1)) - math.Max(x0, float64(sx)))
					p := src.Pix[src.PixOffset(sx, sy):]
					for c := range sum {
						sum[c] += float64(p[c]) * wt
					}
				}
			}
			q := dst.Pix[dst.PixOffset(dx, dy):]
			for c, v := range sum {
				q[c] = uint8(math.Min(255, math.Round(v/area)))
			}
		}
	}
	return dst
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
