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
}
