package model

import "github.com/cedar2025/xboard-node/internal/config"

type NodeSpec struct {
	Protocol        string
	ListenIP        string
	ServerPort      int
	Network         string
	NetworkSettings map[string]any
	Routes          []RouteRule

	KernelType        string
	KernelLogLevel    string
	CustomOutbounds   []OutboundConfig
	CustomRoutes      []map[string]any
	CustomRouteRules  []CustomRouteRule
	PrivateAllowCIDRs []string
	CertConfig        *config.CertConfig
	AutoTLS           bool
	Domain            string

	Cipher    string
	Plugin    string
	PluginOpt string
	ServerKey string

	TLS         int
	Flow        string
	Decryption  string
	TLSSettings map[string]any

	Host       string
	ServerName string

	Version      int
	UpMbps       int
	DownMbps     int
	Obfs         string
	ObfsPassword string

	CongestionControl string
	PaddingScheme     string
	Transport         string
	TrafficPattern    string

	Multiplex           *MultiplexConfig
	AcceptProxyProtocol bool

	// AutoThrottle is the panel-pushed auto-mitigation policy. Nil = disabled.
	AutoThrottle *AutoThrottleConfig

	// ACL is the per-user destination policy. Nil = the panel said nothing,
	// so no enforcement happens at all.
	//
	// The json:"-" tag is load-bearing, not cosmetic. kernel.ComputeHash
	// marshals NodeSpec to decide whether the kernel must be rebuilt, and
	// xray answers a changed hash with a full restart that drops every live
	// connection. ACL is enforced in-process and needs none of that, so it
	// must stay out of the hash. The service folds it into its own config
	// hash separately (see computeConfigHash) so changes are still noticed.
	ACL *ACLConfig `json:"-"`
}

// AutoThrottleConfig is the node-side auto-mitigation policy: when a user's
// throughput stays above ThresholdMbps for TriggerCycles track cycles, the node
// throttles them to PenaltyMbps; if they stay hot for KickAfterCycles more
// cycles it force-closes their connections. The penalty lifts after the user
// has been below the threshold for ReleaseSeconds. All zero = disabled.
type AutoThrottleConfig struct {
	ThresholdMbps   int
	TriggerCycles   int
	PenaltyMbps     int
	KickAfterCycles int
	ReleaseSeconds  int
}

type OutboundConfig struct {
	Tag      string
	Protocol string
	Settings map[string]any
	ProxyTag string
}

type RouteRule struct {
	ID          int
	Match       []string
	Action      string
	ActionValue string
}

type MultiplexConfig struct {
	Enabled        bool
	Protocol       string
	MaxConnections int
	MinStreams     int
	MaxStreams     int
	Padding        bool
	Brutal         *BrutalConfig
}

type BrutalConfig struct {
	Enabled  bool
	UpMbps   int
	DownMbps int
}

type UserSpec struct {
	ID          int
	UUID        string
	SpeedLimit  int
	DeviceLimit int
	// ACLGroups names the ACL groups this user belongs to, already flattened
	// and deduplicated by the panel. Empty = no group, so the node default
	// applies.
	ACLGroups []string
}

func (n *NodeSpec) GetProxyProtocol() bool {
	if n == nil {
		return false
	}
	if n.AcceptProxyProtocol {
		return true
	}
	if n.NetworkSettings != nil {
		if v, ok := n.NetworkSettings["acceptProxyProtocol"]; ok {
			if b, ok := v.(bool); ok {
				return b
			}
		}
	}
	return false
}

func cloneAnyMap(src map[string]any) map[string]any {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]any, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func cloneMapSlice(src []map[string]any) []map[string]any {
	if len(src) == 0 {
		return nil
	}
	out := make([]map[string]any, 0, len(src))
	for _, item := range src {
		out = append(out, cloneAnyMap(item))
	}
	return out
}

func cloneStringSlice(src []string) []string {
	if len(src) == 0 {
		return nil
	}
	out := make([]string, len(src))
	copy(out, src)
	return out
}
