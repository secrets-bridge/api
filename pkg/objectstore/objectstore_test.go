package objectstore

import (
	"strings"
	"testing"
)

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestParseConfig(t *testing.T) {
	cases := []struct {
		name    string
		env     map[string]string
		want    Config
		wantErr string
	}{
		{name: "nothing set is disabled", env: nil, want: Config{}},
		{name: "minimal", env: map[string]string{EnvBucket: "example-bucket", EnvRegion: "eu-west-1"},
			want: Config{Bucket: "example-bucket", Region: "eu-west-1"}},
		{name: "minio", env: map[string]string{
			EnvBucket: "example-bucket", EnvRegion: "us-east-1", EnvEndpoint: "http://minio:9000",
			EnvPathStyle: "true", EnvPrefix: "/sb/uat/",
		}, want: Config{Bucket: "example-bucket", Region: "us-east-1", Endpoint: "http://minio:9000", PathStyle: true, Prefix: "sb/uat"}},
		{name: "path style false", env: map[string]string{EnvBucket: "b", EnvRegion: "r", EnvPathStyle: "false"},
			want: Config{Bucket: "b", Region: "r"}},
		{name: "sse-s3", env: map[string]string{EnvBucket: "b", EnvRegion: "r", EnvSSE: "AES256"},
			want: Config{Bucket: "b", Region: "r", SSE: SSEAES256}},
		{name: "sse-kms", env: map[string]string{EnvBucket: "b", EnvRegion: "r", EnvSSE: "aws:kms", EnvKMSKeyID: "alias/example"},
			want: Config{Bucket: "b", Region: "r", SSE: SSEKMS, KMSKeyID: "alias/example"}},

		{name: "setting without bucket", env: map[string]string{EnvRegion: "r"}, wantErr: EnvBucket},
		{name: "path style without bucket", env: map[string]string{EnvPathStyle: "true"}, wantErr: EnvBucket},
		{name: "no region", env: map[string]string{EnvBucket: "b"}, wantErr: EnvRegion},
		{name: "bad path style", env: map[string]string{EnvBucket: "b", EnvRegion: "r", EnvPathStyle: "yes please"}, wantErr: EnvPathStyle},
		{name: "unknown sse", env: map[string]string{EnvBucket: "b", EnvRegion: "r", EnvSSE: "aes256"}, wantErr: EnvSSE},
		{name: "kms without key", env: map[string]string{EnvBucket: "b", EnvRegion: "r", EnvSSE: "aws:kms"}, wantErr: EnvKMSKeyID},
		{name: "key without kms", env: map[string]string{EnvBucket: "b", EnvRegion: "r", EnvKMSKeyID: "k"}, wantErr: EnvKMSKeyID},
		{name: "endpoint without scheme", env: map[string]string{EnvBucket: "b", EnvRegion: "r", EnvEndpoint: "minio:9000"}, wantErr: EnvEndpoint},
		{name: "dot-dot prefix", env: map[string]string{EnvBucket: "b", EnvRegion: "r", EnvPrefix: "a/../b"}, wantErr: EnvPrefix},
		{name: "empty prefix segment", env: map[string]string{EnvBucket: "b", EnvRegion: "r", EnvPrefix: "a//b"}, wantErr: EnvPrefix},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseConfig(envMap(tc.env))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want one naming %s", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
			if got.Enabled() != (tc.want.Bucket != "") {
				t.Fatalf("Enabled() = %v", got.Enabled())
			}
		})
	}
}

func TestConfigKey(t *testing.T) {
	if k := (Config{}).Key("logos", "team", "id", "abc.png"); k != "logos/team/id/abc.png" {
		t.Fatalf("no prefix: %s", k)
	}
	if k := (Config{Prefix: "sb/uat"}).Key("logos", "team", "id", "abc.png"); k != "sb/uat/logos/team/id/abc.png" {
		t.Fatalf("prefix: %s", k)
	}
}
