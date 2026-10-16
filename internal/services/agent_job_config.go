package services

// agent_job_config.go: what an agent may be told about its provider.
//
// The agent pins its connection (vault address, namespace and auth; aws
// region, roleArn and endpoint) from its own env and fails any job whose
// target_provider_config carries one of those keys or any key it does not
// know (agent internal/executor/resolvers.go). Provider-connection scopes,
// catalog rows and older stored jobs still hold the connection shape, so
// every payload handed to an agent goes through AgentJobProviderConfig.
// The kept keys are still checked on the agent side (vault kvMount and
// kvPrefix must echo its pinned values, an aws tagFilter is ANDed with its
// env filter), so nothing here can widen what an agent reaches.

import "github.com/secrets-bridge/api/pkg/storage"

const (
	jobPayloadProviderType   = "target_provider_type"
	jobPayloadProviderConfig = "target_provider_config"
)

// agentJobConfigKeys maps, per provider type, each key the agent accepts
// in a job payload to the source keys that may hold it, in priority order
// (the agent's own spelling first, so a payload already in agent format
// is kept as is). Provider types not listed get an empty config.
var agentJobConfigKeys = map[string][]struct {
	agentKey string
	from     []string
}{
	string(storage.ProviderConnectionTypeVault): {
		// A provider connection stores the KV v2 mount as "mount".
		{agentKey: "kvMount", from: []string{"kvMount", "mount"}},
		{agentKey: "kvPrefix", from: []string{"kvPrefix"}},
	},
	string(storage.ProviderConnectionTypeAWSSM): {
		{agentKey: "tagFilter", from: []string{"tagFilter", "tag_filter"}},
	},
}

// AgentJobProviderConfig reduces a provider config (a connection scope, a
// catalog provider_config, a stored job payload's target_provider_config)
// to the keys the agent accepts for providerType, renamed to the agent's
// spelling. Everything else is dropped, as are nil and empty-string
// values, which carry no routing. Never returns nil.
func AgentJobProviderConfig[V any](providerType string, src map[string]V) map[string]any {
	out := map[string]any{}
	for _, k := range agentJobConfigKeys[providerType] {
		for _, from := range k.from {
			v, ok := src[from]
			if !ok {
				continue
			}
			val := any(v)
			if val == nil {
				continue
			}
			if s, isString := val.(string); isString && s == "" {
				continue
			}
			out[k.agentKey] = val
			break
		}
	}
	return out
}

// AgentJobPayload returns the payload to hand an agent for a claimed job:
// a shallow copy whose target_provider_config is reduced by
// AgentJobProviderConfig for the payload's target_provider_type. Every
// other field is untouched, and a payload without target_provider_config
// is returned as is. The input map is never modified.
func AgentJobPayload(payload map[string]any) map[string]any {
	raw, ok := payload[jobPayloadProviderConfig]
	if !ok {
		return payload
	}
	providerType, _ := payload[jobPayloadProviderType].(string)
	var cfg map[string]any
	switch m := raw.(type) {
	case map[string]any:
		cfg = AgentJobProviderConfig(providerType, m)
	case map[string]string:
		cfg = AgentJobProviderConfig(providerType, m)
	default:
		// null or not an object: nothing the agent could accept.
		cfg = map[string]any{}
	}
	out := make(map[string]any, len(payload))
	for k, v := range payload {
		out[k] = v
	}
	out[jobPayloadProviderConfig] = cfg
	return out
}
