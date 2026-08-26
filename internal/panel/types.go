package panel

import (
	"encoding/json"
	"fmt"
	"strings"
)

// StringOrArray is a type that can unmarshal from either a JSON string or an array of strings.
// When it's an array, the elements are joined with newlines.
type StringOrArray string

func (s *StringOrArray) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		*s = StringOrArray(str)
		return nil
	}
	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil {
		*s = StringOrArray(strings.Join(arr, "\n"))
		return nil
	}
	return fmt.Errorf("StringOrArray: expected string or []string, got %s", string(data))
}

// HandshakeResponse is the response from POST /api/v2/server/handshake
type HandshakeResponse struct {
	WebSocket WSConfig `json:"websocket"`
	Settings  Settings `json:"settings"`
}

func (h *HandshakeResponse) UnmarshalJSON(data []byte) error {
	type Alias HandshakeResponse
	aux := &struct {
		Settings json.RawMessage `json:"settings"`
		*Alias
	}{
		Alias: (*Alias)(h),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	// If settings is an empty array [], skip unmarshaling it into the struct
	if len(aux.Settings) > 0 && string(aux.Settings) != "[]" {
		if err := json.Unmarshal(aux.Settings, &h.Settings); err != nil {
			return err
		}
	}
	return nil
}

// WSConfig holds WebSocket connection settings from the panel
type WSConfig struct {
	Enabled bool   `json:"enabled"`
	WSURL   string `json:"ws_url,omitempty"`
}

// Settings holds panel-defined intervals
type Settings struct {
	PushInterval int `json:"push_interval"`
	PullInterval int `json:"pull_interval"`
}

// MachineNode is a single entry returned by GET /api/v2/server/machine/nodes.
type MachineNode struct {
	ID   int    `json:"id"`
	Type string `json:"type"`
	Name string `json:"name"`
}

// MachineNodesResponse is the response from GET /api/v2/server/machine/nodes.
type MachineNodesResponse struct {
	Nodes      []MachineNode     `json:"nodes"`
	BaseConfig MachineBaseConfig `json:"base_config"`
	// Absent when the panel has no desired version configured.
	Agent *AgentTarget `json:"agent"`
}

// AgentTarget is the panel's desired agent version for this machine.
type AgentTarget struct {
	TargetVersion string `json:"target_version"`
	InstallerURL  string `json:"installer_url"`
}

// MachineBaseConfig holds polling intervals for machine mode.
type MachineBaseConfig struct {
	PushInterval int `json:"push_interval"`
	PullInterval int `json:"pull_interval"`
}

// NodeConfig is the response from GET /api/v1/server/UniProxy/config
type NodeConfig struct {
	// NodeID is populated in machine-mode WS events for routing.
	NodeID          int                    `json:"node_id,omitempty"`
	Protocol        string                 `json:"protocol"`
	ListenIP        string                 `json:"listen_ip"`
	ServerPort      int                    `json:"server_port"`
	Network         string                 `json:"network"`
	NetworkSettings map[string]interface{} `json:"networkSettings"`
	BaseConfig      BaseConfig             `json:"base_config"`
	Routes          []RouteRule            `json:"routes"`

	// Kernel settings (Xboard extension)
	KernelType       string            `json:"kernel_type,omitempty"`      // "singbox" or "xray"
	KernelLogLevel   string            `json:"kernel_log_level,omitempty"` // "info", "warn", etc.
	CustomOutbounds  []OutboundConfig  `json:"custom_outbounds,omitempty"`
	CustomRoutes     []map[string]any  `json:"custom_routes,omitempty"`
	CustomRouteRules []CustomRouteRule `json:"custom_route_rules,omitempty"`

	// PrivateAllowCIDRs lists internal networks that may be reached through this
	// node. The kernel blocks every private range by default (SSRF guard); these
	// entries are emitted *before* that block so they win.
	//
	// Empty (or absent) keeps the old behaviour: all private ranges blocked.
	PrivateAllowCIDRs []string `json:"private_allow_cidrs,omitempty"`

	// Certificate settings (Xboard extension)
	CertConfig *CertConfig `json:"cert_config,omitempty"`
	AutoTLS    bool        `json:"auto_tls,omitempty"` // Deprecated: use CertConfig
	Domain     string      `json:"domain,omitempty"`   // Deprecated: use CertConfig

	// Shadowsocks
	Cipher    string `json:"cipher,omitempty"`
	Plugin    string `json:"plugin,omitempty"`
	PluginOpt string `json:"plugin_opts,omitempty"`
	ServerKey string `json:"server_key,omitempty"`

	// VMess / VLESS
	TLS         int                    `json:"tls,omitempty"`
	Flow        string                 `json:"flow,omitempty"`
	Decryption  string                 `json:"decryption,omitempty"`
	TLSSettings map[string]interface{} `json:"tls_settings,omitempty"`

	// Trojan
	Host       string `json:"host,omitempty"`
	ServerName string `json:"server_name,omitempty"`

	// Hysteria
	Version      int    `json:"version,omitempty"`
	UpMbps       int    `json:"up_mbps,omitempty"`
	DownMbps     int    `json:"down_mbps,omitempty"`
	Obfs         string `json:"obfs,omitempty"`
	ObfsPassword string `json:"obfs-password,omitempty"`

	// TUIC
	CongestionControl string `json:"congestion_control,omitempty"`

	// AnyTLS
	PaddingScheme StringOrArray `json:"padding_scheme,omitempty"`

	// Mieru
	Transport      string `json:"transport,omitempty"`
	TrafficPattern string `json:"traffic_pattern,omitempty"`

	// Multiplex
	Multiplex *MultiplexConfig `json:"multiplex,omitempty"`

	// Proxy Protocol (supports both top-level and networkSettings for compatibility)
	AcceptProxyProtocol bool `json:"accept_proxy_protocol,omitempty"`

	// AutoThrottle is the node-side auto-mitigation policy (Xboard extension).
	AutoThrottle *AutoThrottleConfig `json:"auto_throttle,omitempty"`

	// ACL is the per-user destination policy. A pointer so that "the panel
	// never mentioned ACL" (nil) stays distinguishable from "the panel sent
	// a policy that happens to be empty" — the first must behave exactly as
	// the node did before ACL existed. See docs-user-acl.md §3.4.
	ACL *ACLConfig `json:"acl,omitempty"`
}

// ACLConfig mirrors model.ACLConfig on the wire.
type ACLConfig struct {
	Mode          string `json:"mode"`
	DefaultAction string `json:"default_action"`
	// ImplicitDNSAllow is a pointer so an omitted field means "default true"
	// rather than "false" — losing DNS under a deny default makes a healthy
	// node look dead.
	ImplicitDNSAllow *bool      `json:"implicit_dns_allow,omitempty"`
	Groups           []ACLGroup `json:"groups,omitempty"`
}

// ACLGroup mirrors model.ACLGroup on the wire.
type ACLGroup struct {
	ID            string    `json:"id"`
	Priority      int       `json:"priority,omitempty"`
	DefaultAction string    `json:"default_action,omitempty"`
	Rules         []ACLRule `json:"rules,omitempty"`
}

// ACLRule mirrors model.ACLRule on the wire.
type ACLRule struct {
	Action         string   `json:"action"`
	Priority       int      `json:"priority,omitempty"`
	IPCIDRs        []string `json:"ip_cidrs,omitempty"`
	Domains        []string `json:"domains,omitempty"`
	DomainSuffixes []string `json:"domain_suffixes,omitempty"`
	Ports          []string `json:"ports,omitempty"`
	Protocols      []string `json:"protocols,omitempty"`
}

// AutoThrottleConfig mirrors model.AutoThrottleConfig on the wire.
type AutoThrottleConfig struct {
	ThresholdMbps   int `json:"threshold_mbps"`
	TriggerCycles   int `json:"trigger_cycles"`
	PenaltyMbps     int `json:"penalty_mbps"`
	KickAfterCycles int `json:"kick_after_cycles"`
	ReleaseSeconds  int `json:"release_seconds"`
}

// GetProxyProtocol returns true if AcceptProxyProtocol is set either at node level
// or in networkSettings (for panel compatibility).
func (nc *NodeConfig) GetProxyProtocol() bool {
	if nc.AcceptProxyProtocol {
		return true
	}
	if nc.NetworkSettings != nil {
		if v, ok := nc.NetworkSettings["acceptProxyProtocol"]; ok {
			if b, ok := v.(bool); ok {
				return b
			}
		}
	}
	return false
}

type MultiplexConfig struct {
	Enabled        bool          `json:"enabled"`
	Protocol       string        `json:"protocol"`
	MaxConnections int           `json:"max_connections"`
	MinStreams     int           `json:"min_streams"`
	MaxStreams     int           `json:"max_streams"`
	Padding        bool          `json:"padding"`
	Brutal         *BrutalConfig `json:"brutal,omitempty"`
}

type BrutalConfig struct {
	Enabled  bool `json:"enabled"`
	UpMbps   int  `json:"up_mbps"`
	DownMbps int  `json:"down_mbps"`
}

// CertConfig holds certificate automation settings from the panel.
// The panel may send the mode field as either "cert_mode" or "mode";
// a custom UnmarshalJSON handles both.
type CertConfig struct {
	CertMode    string            `json:"cert_mode"`    // none, dns, http, self, file, content
	Domain      string            `json:"domain"`       // Certificate domain
	Email       string            `json:"email"`        // ACME email
	DNSProvider string            `json:"dns_provider"` // dns mode: cloudflare, alidns, etc.
	DNSEnv      map[string]string `json:"dns_env"`      // Provider-specific API keys/tokens
	HTTPPort    int               `json:"http_port"`    // ACME HTTP-01 local port (default 80)
	CertFile    string            `json:"cert_file"`    // file mode: path to cert file
	KeyFile     string            `json:"key_file"`     // file mode: path to key file
	CertContent string            `json:"cert_content"` // content mode: certificate raw string
	KeyContent  string            `json:"key_content"`  // content mode: private key raw string
}

func (c *CertConfig) UnmarshalJSON(data []byte) error {
	type plain CertConfig
	var raw struct {
		plain
		ModeFallback string `json:"mode"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*c = CertConfig(raw.plain)
	if c.CertMode == "" && raw.ModeFallback != "" {
		c.CertMode = raw.ModeFallback
	}
	return nil
}

// OutboundConfig defines a custom outbound for kernel
type OutboundConfig struct {
	Tag      string         `json:"tag"`                 // Unique tag for routing
	Protocol string         `json:"protocol"`            // vmess, vless, shadowsocks, wireguard, etc.
	Settings map[string]any `json:"settings,omitempty"`  // Protocol-specific settings
	ProxyTag string         `json:"proxy_tag,omitempty"` // Chain proxy: next outbound tag
}

type BaseConfig struct {
	PushInterval int `json:"push_interval"`
	PullInterval int `json:"pull_interval"`
}

type RouteRule struct {
	ID          int      `json:"id"`
	Match       []string `json:"match"`
	Action      string   `json:"action"`
	ActionValue string   `json:"action_value,omitempty"`
}

type CustomRouteRule struct {
	Name     string      `json:"name,omitempty"`
	Disabled bool        `json:"disabled,omitempty"`
	Match    RouteMatch  `json:"match,omitempty"`
	Action   RouteAction `json:"action"`
}

type RouteMatch struct {
	Domains        []string `json:"domains,omitempty"`
	DomainSuffixes []string `json:"domain_suffixes,omitempty"`
	IPCIDRs        []string `json:"ip_cidrs,omitempty"`
	Ports          []string `json:"ports,omitempty"`
	Networks       []string `json:"networks,omitempty"`
	SourceCIDRs    []string `json:"source_cidrs,omitempty"`
	SourcePorts    []string `json:"source_ports,omitempty"`
}

type RouteAction struct {
	Type   string `json:"type"`
	Target string `json:"target,omitempty"`
}

// User represents a user returned by the panel
type User struct {
	ID          int    `json:"id"`
	UUID        string `json:"uuid"`
	SpeedLimit  int    `json:"speed_limit"`  // Mbps, 0 = unlimited
	DeviceLimit int    `json:"device_limit"` // max devices, 0 = unlimited
	// ACLGroups lists the ACL group IDs this user belongs to, already merged
	// and deduplicated panel-side. Absent or empty = no group.
	ACLGroups []string `json:"acl_groups,omitempty"`
}

type UsersResponse struct {
	Users []User `json:"users"`
}
