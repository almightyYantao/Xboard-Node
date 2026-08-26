package model

// AccessRecord 是一条连接级访问日志：用户访问了哪个目标（域名/IP）及其流量。
// 仅在节点开启 access_log 时采集，由 kernel 缓冲、service 周期性上报面板，
// 面板再转发到外部日志后端（不落库）。
type AccessRecord struct {
	Time       int64  `json:"time"`           // 连接结束时间，unix 毫秒
	UserID     int    `json:"user_id"`        // 用户 ID（面板侧映射邮箱）
	SourceIP   string `json:"source_ip"`      // 客户端来源 IP
	DestHost   string `json:"dest_host"`      // 目标域名；无域名时为目标 IP
	DestPort   int    `json:"dest_port"`      // 目标端口
	Network    string `json:"network"`        // tcp / udp
	Upload     int64  `json:"upload_bytes"`   // 该连接上行字节
	Download   int64  `json:"download_bytes"` // 该连接下行字节
	DurationMs int64  `json:"duration_ms"`    // 连接时长（毫秒）
	Reason     string `json:"reason,omitempty"` // 出站拨号失败原因（成功为空）

	// 以下三个字段仅出现在 ACL 拒绝记录里，普通访问日志为空。
	// ACL 记录在连接建立时就产生（而非结束时），因此没有流量与时长 ——
	// Upload/Download/DurationMs 恒为 0，面板按 acl_action 非空来区分。
	//
	// 这类记录不受 access_log 开关约束：运营开 dryrun 就是为了看影响面，
	// 不该被迫同时打开全量访问日志那个数量级大得多的水管。
	ACLMode   string `json:"acl_mode,omitempty"`   // dryrun / enforce
	ACLAction string `json:"acl_action,omitempty"` // 目前只记录 deny
	ACLRule   string `json:"acl_rule,omitempty"`   // 命中规则，如 "vip#2"；兜底为 "default"
}

// IsACL 表示这是一条 ACL 判定记录而非普通访问日志。
func (r AccessRecord) IsACL() bool { return r.ACLAction != "" }
