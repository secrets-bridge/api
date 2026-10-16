package services_test

import (
	"reflect"
	"testing"

	"github.com/secrets-bridge/api/internal/services"
)

func TestAgentJobProviderConfig(t *testing.T) {
	tagFilter := map[string]any{"EnvironmentName": "tenant-a-uat"}
	cases := []struct {
		name         string
		providerType string
		src          map[string]any
		want         map[string]any
	}{
		{
			name:         "vault connection scope maps mount to kvMount",
			providerType: "vault",
			src:          map[string]any{"address": "https://vault.example.com", "mount": "secret"},
			want:         map[string]any{"kvMount": "secret"},
		},
		{
			name:         "vault full scope keeps kvMount and kvPrefix only",
			providerType: "vault",
			src: map[string]any{
				"address": "https://vault.example.com", "mount": "secret",
				"namespace": "team-alpha", "kvPrefix": "team-alpha/uat",
			},
			want: map[string]any{"kvMount": "secret", "kvPrefix": "team-alpha/uat"},
		},
		{
			name:         "vault agent format passes through",
			providerType: "vault",
			src:          map[string]any{"kvMount": "secret", "kvPrefix": "team-alpha"},
			want:         map[string]any{"kvMount": "secret", "kvPrefix": "team-alpha"},
		},
		{
			name:         "vault kvMount wins over mount",
			providerType: "vault",
			src:          map[string]any{"kvMount": "kv", "mount": "secret"},
			want:         map[string]any{"kvMount": "kv"},
		},
		{
			name:         "vault steering, credential and unknown keys dropped",
			providerType: "vault",
			src: map[string]any{
				"address": "https://vault.example.com", "namespace": "team-alpha",
				"authMethod": "token", "auth_method": "token", "token": "x",
				"kubernetesRole": "r", "kubernetesMountPath": "m",
				"kubernetesTokenPath": "/etc/passwd", "prefix": "team-alpha", "other": "x",
			},
			want: map[string]any{},
		},
		{
			name:         "vault blank and null values carry nothing",
			providerType: "vault",
			src:          map[string]any{"mount": "", "kvMount": nil, "kvPrefix": ""},
			want:         map[string]any{},
		},
		{
			name:         "blank kvMount falls back to mount",
			providerType: "vault",
			src:          map[string]any{"kvMount": "", "mount": "secret"},
			want:         map[string]any{"kvMount": "secret"},
		},
		{
			name:         "aws connection scope keeps nothing",
			providerType: "aws-sm",
			src: map[string]any{
				"region": "us-east-1", "roleArn": "arn:aws:iam::123456789012:role/sb-agent",
				"endpoint": "https://secretsmanager.example.com",
			},
			want: map[string]any{},
		},
		{
			name:         "aws tagFilter kept",
			providerType: "aws-sm",
			src:          map[string]any{"region": "us-east-1", "tagFilter": tagFilter},
			want:         map[string]any{"tagFilter": tagFilter},
		},
		{
			name:         "aws tag_filter renamed",
			providerType: "aws-sm",
			src:          map[string]any{"tag_filter": tagFilter},
			want:         map[string]any{"tagFilter": tagFilter},
		},
		{
			name:         "aws credentials dropped",
			providerType: "aws-sm",
			src:          map[string]any{"accessKeyID": "x", "secretAccessKey": "y", "credentials": "z"},
			want:         map[string]any{},
		},
		{
			name:         "vault keys mean nothing for aws",
			providerType: "aws-sm",
			src:          map[string]any{"kvMount": "secret", "mount": "secret"},
			want:         map[string]any{},
		},
		{
			name:         "provider without an agent resolver",
			providerType: "gcp-sm",
			src:          map[string]any{"projectID": "tenant-a-uat"},
			want:         map[string]any{},
		},
		{
			name:         "empty provider type",
			providerType: "",
			src:          map[string]any{"kvMount": "secret"},
			want:         map[string]any{},
		},
		{
			name:         "nil config",
			providerType: "vault",
			src:          nil,
			want:         map[string]any{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := services.AgentJobProviderConfig(tc.providerType, tc.src)
			if got == nil {
				t.Fatal("got nil map, want non-nil")
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// Provider-connection scopes are map[string]string.
func TestAgentJobProviderConfig_StringScope(t *testing.T) {
	scope := map[string]string{"address": "https://vault.example.com", "mount": "secret", "kvPrefix": "team-alpha"}
	got := services.AgentJobProviderConfig("vault", scope)
	want := map[string]any{"kvMount": "secret", "kvPrefix": "team-alpha"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestAgentJobPayload(t *testing.T) {
	t.Run("translates config, keeps other fields, leaves input alone", func(t *testing.T) {
		in := map[string]any{
			"request_id":             "r1",
			"target_provider_type":   "vault",
			"target_provider_config": map[string]any{"address": "https://vault.example.com", "mount": "secret"},
			"target_secret_ref":      "team-alpha/uat/db",
			"wraps":                  []any{map[string]any{"wrap_id": "w1", "key_name": "DB_PASSWORD"}},
		}
		got := services.AgentJobPayload(in)
		want := map[string]any{
			"request_id":             "r1",
			"target_provider_type":   "vault",
			"target_provider_config": map[string]any{"kvMount": "secret"},
			"target_secret_ref":      "team-alpha/uat/db",
			"wraps":                  []any{map[string]any{"wrap_id": "w1", "key_name": "DB_PASSWORD"}},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
		if _, still := in["target_provider_config"].(map[string]any)["address"]; !still {
			t.Error("input payload was modified")
		}
	})

	t.Run("no config key is left absent", func(t *testing.T) {
		in := map[string]any{"target_provider_type": "vault", "scope": "team-alpha"}
		got := services.AgentJobPayload(in)
		if _, ok := got["target_provider_config"]; ok {
			t.Errorf("target_provider_config added: %v", got)
		}
		if !reflect.DeepEqual(got, in) {
			t.Errorf("got %v, want %v", got, in)
		}
	})

	t.Run("string map config", func(t *testing.T) {
		got := services.AgentJobPayload(map[string]any{
			"target_provider_type":   "vault",
			"target_provider_config": map[string]string{"address": "https://vault.example.com", "mount": "secret"},
		})
		if want := map[string]any{"kvMount": "secret"}; !reflect.DeepEqual(got["target_provider_config"], want) {
			t.Errorf("config = %v, want %v", got["target_provider_config"], want)
		}
	})

	for name, raw := range map[string]any{"null": nil, "string": "https://vault.example.com", "list": []any{"x"}} {
		t.Run("non-object config becomes empty: "+name, func(t *testing.T) {
			got := services.AgentJobPayload(map[string]any{
				"target_provider_type":   "vault",
				"target_provider_config": raw,
			})
			if want := map[string]any{}; !reflect.DeepEqual(got["target_provider_config"], want) {
				t.Errorf("config = %#v, want {}", got["target_provider_config"])
			}
		})
	}

	t.Run("nil payload", func(t *testing.T) {
		if got := services.AgentJobPayload(nil); got != nil {
			t.Errorf("got %v, want nil", got)
		}
	})
}
