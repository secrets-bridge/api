package services

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"math/rand/v2"
	"testing"
)

// gradient is a w×h opaque test image.
func gradient(w, h int) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := range h {
		for x := range w {
			img.SetRGBA(x, y, color.RGBA{R: uint8(x * 255 / w), G: uint8(y * 255 / h), B: 120, A: 255})
		}
	}
	return img
}

func decodeStored(t *testing.T, b []byte) image.Config {
	t.Helper()
	cfg, err := png.DecodeConfig(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("stored bytes are not a PNG: %v", err)
	}
	return cfg
}

func TestEncodeLogo_FitsTheLongerSideKeepingAspect(t *testing.T) {
	cases := []struct{ w, h, wantW, wantH int }{
		{512, 384, 128, 96},
		{384, 512, 96, 128},
		{512, 16, 128, 4},
		{200, 200, 128, 128},
		{128, 128, 128, 128},
		{64, 40, 64, 40}, // already small: stored at its own size
	}
	for _, tc := range cases {
		b, bounds, err := encodeLogo(gradient(tc.w, tc.h))
		if err != nil {
			t.Fatalf("%dx%d: %v", tc.w, tc.h, err)
		}
		cfg := decodeStored(t, b)
		if cfg.Width != tc.wantW || cfg.Height != tc.wantH || bounds.Dx() != tc.wantW || bounds.Dy() != tc.wantH {
			t.Errorf("%dx%d stored as %dx%d (bounds %v), want %dx%d", tc.w, tc.h, cfg.Width, cfg.Height, bounds, tc.wantW, tc.wantH)
		}
	}
}

// A decoded JPEG is YCbCr, which the PNG encoder writes as 16-bit RGB.
// The stored logo is 8-bit.
func TestEncodeLogo_JPEGIsStoredAsEightBit(t *testing.T) {
	var jb bytes.Buffer
	if err := jpeg.Encode(&jb, gradient(128, 128), &jpeg.Options{Quality: 80}); err != nil {
		t.Fatal(err)
	}
	img, err := jpeg.Decode(bytes.NewReader(jb.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := img.(*image.YCbCr); !ok {
		t.Fatalf("fixture decoded as %T, want *image.YCbCr", img)
	}
	b, _, err := encodeLogo(img)
	if err != nil {
		t.Fatal(err)
	}
	if cfg := decodeStored(t, b); cfg.ColorModel != color.RGBAModel {
		t.Errorf("stored color model %T, want 8-bit RGB", cfg.ColorModel)
	}
	direct, err := encodeLogoPNG(img)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) >= len(direct) {
		t.Errorf("8-bit PNG is %d bytes, the 16-bit one %d; want smaller", len(b), len(direct))
	}
}

// Random pixels with random alpha don't compress: at 128 px the PNG is
// over 64 KiB, so the service steps down to the next size.
func TestEncodeLogo_StepsDownWhenStillTooLarge(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 4))
	noise := image.NewNRGBA(image.Rect(0, 0, 128, 128))
	for i := range noise.Pix {
		noise.Pix[i] = uint8(rng.UintN(256))
	}
	if b, _ := encodeLogoPNG(toRGBA(noise)); len(b) <= LogoMaxBytes {
		t.Fatalf("fixture encodes to %d bytes at 128 px; it must be over the cap to test the step down", len(b))
	}
	b, bounds, err := encodeLogo(noise)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > LogoMaxBytes {
		t.Fatalf("stored %d bytes, over the cap", len(b))
	}
	if bounds.Dx() != 96 || bounds.Dy() != 96 {
		t.Errorf("stored %v, want 96x96", bounds)
	}
}

func TestScaleDown_AveragesAreas(t *testing.T) {
	// Black and white columns average to mid grey.
	checker := image.NewRGBA(image.Rect(0, 0, 2, 2))
	checker.SetRGBA(0, 0, color.RGBA{A: 255})
	checker.SetRGBA(0, 1, color.RGBA{A: 255})
	checker.SetRGBA(1, 0, color.RGBA{R: 255, G: 255, B: 255, A: 255})
	checker.SetRGBA(1, 1, color.RGBA{R: 255, G: 255, B: 255, A: 255})
	if got := scaleDown(checker, 1, 1).RGBAAt(0, 0); got != (color.RGBA{R: 128, G: 128, B: 128, A: 255}) {
		t.Errorf("black|white = %v, want mid grey", got)
	}

	// Transparent next to opaque red is red at half alpha, not a darker
	// red: the average is taken on premultiplied values.
	edge := image.NewRGBA(image.Rect(0, 0, 2, 1))
	edge.SetRGBA(1, 0, color.RGBA{R: 255, A: 255})
	got := color.NRGBAModel.Convert(scaleDown(edge, 1, 1).RGBAAt(0, 0)).(color.NRGBA)
	if got.R < 254 || got.A != 128 {
		t.Errorf("transparent|red = %v, want R 255 at alpha 128", got)
	}

	// A uniform image stays uniform at a non-integer ratio.
	flat := image.NewRGBA(image.Rect(0, 0, 300, 200))
	for i := 0; i < len(flat.Pix); i += 4 {
		copy(flat.Pix[i:], []uint8{10, 200, 30, 255})
	}
	out := scaleDown(flat, 128, 85)
	for i := 0; i < len(out.Pix); i += 4 {
		if p := out.Pix[i : i+4]; p[0] != 10 || p[1] != 200 || p[2] != 30 || p[3] != 255 {
			t.Fatalf("pixel %d = %v, want 10,200,30,255", i/4, p)
		}
	}
}
