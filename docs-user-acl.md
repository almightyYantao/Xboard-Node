# 用户级 ACL —— 面板侧改造规范 v1

> 本文是 **面板 ↔ 节点的契约**。节点严格按本文解析下发数据；面板未按本文实现的字段会被
> 静默忽略（见 §10 的 mapstructure 陷阱）。实现前请先通读 §9 验收清单。

节点侧实现方式：进程内 ACL（在 `xray/dispatcher.go` 与 `singbox/conntracker.go` 已有的
每连接钩子上判定），**不经过内核路由规则**。因此策略变更是内存热更新，不重启内核、不断连接。

---

## 1. 面板改动清单

| # | 模块 | 改什么 | 验收点 |
|---|------|--------|--------|
| 1 | DB 迁移 | ACL 组表、规则表、关联表、节点级开关字段 | §2 |
| 2 | 节点配置接口 | `GET /api/v1/server/UniProxy/config` + `/api/v2/server/config` 返回体加 `acl` 对象 | §3.1 |
| 3 | 用户接口 | `GET /api/v1/server/UniProxy/user` + `/api/v2/server/user` 每个 user 加 `acl_groups` | §3.2 |
| 4 | **ETag** | 两个接口的 ETag 必须覆盖 ACL 数据 | §5 —— **最易漏，漏了策略永不生效** |
| 5 | WS 推送 | ACL 变更推 `sync.config`；用户归属变更推 `sync.users` / `sync.user.delta` | §6 |
| 6 | 校验 | 保存时校验，不得把非法数据推给节点 | §4 |
| 7 | 后台 UI | 组管理、用户组关联、节点开关、default deny 二次确认 | §8 |
| 8 | dryrun 视图 | 展示"若 enforce 会被拦截"的连接 | §7 |

---

## 2. 数据模型建议

对端为自研 Python 面板，下面只给字段语义，表名、ORM、迁移工具按你们现有约定。

```
acl_group
  id            string(32)   -- 对外 ID，^[a-z0-9_-]{1,32}$，下发时用这个而非自增主键
  name          string       -- 展示名
  priority      int          -- 越小越先求值，默认 100
  default_action enum(allow,deny,inherit) default 'inherit'
  enabled       bool
  remark        text

acl_rule
  id            bigint
  acl_group_id  string(32)
  action        enum(allow,deny)
  priority      int          -- 组内顺序，越小越先
  ip_cidrs        json  -- ["10.0.0.0/8", ...]
  domain_suffixes json  -- ["corp.example.com", ...]
  domains         json  -- 精确匹配
  ports           json  -- ["443", "8000-9000"]
  protocols       json  -- ["tcp","udp"]，空=全部
  enabled       bool

acl_group_user_group   -- ACL 组 ↔ 现有「用户组」，主要关联方式
  acl_group_id, user_group_id

acl_group_user         -- 单用户 override，应付特例
  acl_group_id, user_id

-- 节点表新增
node.acl_mode            enum(off,dryrun,enforce) default 'off'
node.acl_default_action  enum(allow,deny)         default 'allow'
```

**为什么 ACL 组主要绑「用户组」**：节点侧按组做策略对象共享（interning），组数决定内存与
匹配成本，用户数几乎不影响 —— 5000 用户 / 100 组 / 每组 500 CIDR 常驻 2.8 MB，若改成每用户
独立编译则是 117.9 MB。绑用户组也复用了运营既有的心智。

> **JSON 列注意**：`ip_cidrs` 等字段若用 JSON/JSONB 列存储，取出后必须是 Python `list`，
> 不能是尚未 `json.loads` 的 `str`。SQLAlchemy 用 `JSON`/`JSONB` 类型而非 `Text`，
> 否则会踩 §10 陷阱 3。

---

## 3. 下发协议

关键词 MUST / MUST NOT / SHOULD 按 RFC 2119 理解。

### 3.1 NodeConfig 新增 `acl`

```jsonc
{
  "protocol": "vless",
  "server_port": 443,
  // ... 现有字段不变 ...
  "acl": {
    "mode": "enforce",              // off | dryrun | enforce
    "default_action": "deny",       // allow | deny
    "implicit_dns_allow": true,     // deny 模式下是否隐含放行 53 端口
    "groups": [
      {
        "id": "vip",
        "priority": 10,
        "default_action": null,      // null = 继承 acl.default_action
        "rules": [
          {
            "action": "allow",
            "priority": 10,
            "ip_cidrs": ["10.1.0.0/16", "203.0.113.0/24"],
            "domain_suffixes": ["corp.example.com"],
            "ports": ["443", "8000-9000"],
            "protocols": ["tcp"]
          }
        ]
      },
      {
        "id": "restricted",
        "priority": 20,
        "default_action": null,
        "rules": [
          { "action": "deny", "priority": 10, "ip_cidrs": ["10.0.0.0/8"] }
        ]
      }
    ]
  }
}
```

同一个 NodeConfig 上还有一个**与 `acl` 平级**的字段，见 §3.5 —— 它必须放在 `acl` 外面：

```jsonc
{
  "acl": { /* ... */ },
  "acl_resolve_domains": ["qunhequnhe.com"]   // 与 acl 平级，不在 acl 里面
}
```

| 字段 | 类型 | 必填 | 默认 | 约束 |
|------|------|------|------|------|
| `acl` | object | 否 | **缺失 = ACL 完全禁用** | 见 §3.4 |
| `acl_resolve_domains` | string[] | 否 | `[]` | 域名后缀，**与 `acl` 平级**，见 §3.5 |
| `acl.mode` | string | 是 | — | `off` / `dryrun` / `enforce` |
| `acl.default_action` | string | 是 | — | `allow` / `deny` |
| `acl.implicit_dns_allow` | bool | 否 | `true` | 见 §8 |
| `acl.groups[]` | array | 是 | `[]` | 可为空数组 |
| `groups[].id` | string | 是 | — | `^[a-z0-9_-]{1,32}$`，节点内唯一 |
| `groups[].priority` | int | 否 | `100` | 越小越先求值 |
| `groups[].default_action` | string\|null | 否 | `null` | `allow` / `deny` / `null`(继承) |
| `groups[].rules[]` | array | 是 | `[]` | |
| `rules[].action` | string | 是 | — | `allow` / `deny` |
| `rules[].priority` | int | 否 | `100` | 组内顺序 |
| `rules[].ip_cidrs` | string[] | 否 | `[]` | 合法 CIDR，见 §4 |
| `rules[].domains` | string[] | 否 | `[]` | 精确域名 |
| `rules[].domain_suffixes` | string[] | 否 | `[]` | 后缀，不带前导 `.` |
| `rules[].ports` | string[] | 否 | `[]` | `"N"` 或 `"N-M"` |
| `rules[].protocols` | string[] | 否 | `[]`(=全部) | `tcp` / `udp` |

匹配语义分三组，**组内 OR，组间 AND**：

```
目标组 (ip_cidrs | domains | domain_suffixes)  AND  ports  AND  protocols
```

三个目标匹配器合成**一个 OR 组**，而不是三个独立的 AND 条件。原因是一次连接的目标要么
是地址、要么是主机名，不可能两者皆是 —— 若跨类型 AND，上面那条同时写了 `ip_cidrs` 和
`domain_suffixes` 的示例规则将**永远不可能命中**。空的组匹配一切。

这与现有 `custom_route_rules` 的语义**不同**（后者每个维度被拆成独立规则，整体是 OR），
面板 UI 的文案必须写清楚，否则运营会配错。

### 3.2 User 新增 `acl_groups`

```jsonc
{
  "users": [
    { "id": 1001, "uuid": "550e8400-...", "speed_limit": 0, "device_limit": 3,
      "acl_groups": ["vip"] },
    { "id": 1002, "uuid": "6ba7b810-...", "speed_limit": 0, "device_limit": 0,
      "acl_groups": [] }
  ]
}
```

- `acl_groups` 是 `string[]`，元素为 `groups[].id`。
- 面板 MUST 已合并「用户组关联 + 单用户 override」后再下发扁平数组，节点不做关联计算。
- 面板 MUST 去重。
- 引用了不存在的 group id 时，节点忽略该项并告警；面板 SHOULD 在删除组时清理关联。
- 字段缺失或为 `[]` = 该用户不属于任何组 → 落 `acl.default_action`。

### 3.3 判定语义

节点按下列顺序求值，**面板的 UI 预览/模拟器必须实现完全相同的算法**，否则运营看到的
和线上跑的不一致：

```
policy_of(user):
    groups = sort(user.acl_groups, by group.priority asc, then id asc)
    rules  = []
    for g in groups:
        rules += sort(g.rules, by priority asc, then array index asc)
    return rules, first_non_null([g.default_action for g in groups]) ?? acl.default_action

match_once(policy, dest_ip, dest_domain, port, proto):
    for r in policy.rules:
        if matches(r, ...): return r.action, r.origin   # 第一条命中即决定
    return policy.default_action, "default"

check(user, dest_ip, dest_domain, port, proto, resolved_ips):
    p = policy_of(user)
    action, origin = match_once(p, dest_ip, dest_domain, port, proto)
    if origin != "default" or dest_domain is null or resolved_ips is empty:
        return action, origin
    # 域名没命中任何规则，改用内核已解析出的地址再判
    for addr in resolved_ips:                            # 任一 deny 即 deny
        a, o = match_once(p, addr, null, port, proto)
        if a == deny: return deny, o
    return allow, first_explicit_origin_seen ?? "default"
```

要点：
- **首条命中即返回**，不做"deny 优先"之类的隐式覆盖。顺序完全由 priority 决定。
- 组级 `default_action` 取**优先级最高的那个非 null 组**的值；都为 null 则用节点级。
- 目标是域名时先只走域名维度。**节点自己不会为了匹配 IP 规则去解析域名** —— 每连接
  一次 DNS 会比 ~35 ns 的匹配贵五个数量级。
- 但如果内核在路由阶段**已经**解析过（sing-box 的 `resolve` route action 会填
  `DestinationAddresses` 而不改写 `Destination`），且域名维度**没有命中任何规则**，
  节点会拿这些地址再判一轮，于是 `ip_cidrs` 也能管住域名寻址的流量。这是节点侧
  配置项，面板无需下发任何新字段。
- 命名了域名的规则**优先于**解析地址：运营写了域名就是表达了对这个名字的意图，
  allow/deny 两个方向都按它决定，解析地址不再参与。
- 多个解析地址的聚合是**故意不对称的：任一地址被拒则整条连接被拒**。内核可能拨任意
  一个地址、还可能故障转移，所以"至少有一个被放行就放行"会让白名单被一个混合
  DNS 应答绕过；同样，黑名单也不能让一个被禁地址躲在允许地址后面。
- 域名寻址 + 只配 `ip_cidrs` + 节点未开 `resolve`，结果仍然是落到 default。面板 UI
  MUST 在这种组合下引导运营补 `domain_suffixes`，或提示节点侧启用 `resolve`。
- **xray 节点不支持解析回退**：ACL 钩子在 `Dispatch` 里，比路由更早，拿不到任何已解析
  地址。xray 上只能配 `domain_suffixes`。面板模拟器若要区分内核，需要按节点类型给出
  不同预览。

### 3.4 缺失 vs 空 —— 最关键的一组语义

| 下发内容 | 节点行为 |
|---|---|
| `acl` 字段**不存在** | ACL 完全禁用，行为与改造前 100% 一致（老面板兼容路径） |
| `acl.mode = "off"` | 同上，但节点知道面板支持 ACL |
| `acl.mode = "dryrun"` | 判定并上报，**不拦截** |
| `acl.mode = "enforce"`, `groups = []`, `default_action = "allow"` | 全放行 |
| `acl.mode = "enforce"`, `groups = []`, `default_action = "deny"` | **全阻断**（合法但危险，见 §8） |

面板 MUST NOT 用 `acl: null`、`acl: []`、`acl: {}` 表达"关闭" —— 关闭请用
`mode: "off"` 或整个字段不下发。节点对 `acl` 存在但缺 `mode`/`default_action` 的情况
按解析失败处理：保留上一次生效策略并告警。

### 3.5 `acl_resolve_domains` —— 让 `ip_cidrs` 管住域名寻址的流量

客户端交给节点的目标通常是**域名**（vless/vmess 协议头里就是主机名；客户端本地那套
fake-ip / `nameserver-policy` 只影响客户端自己的选路）。域名目标匹配不上 `ip_cidrs`，
所以"只放行某个内网段"的策略在 default deny 下会把这类流量全拦掉 —— 恰好是它本来
想放行的那部分。

面板下发要让节点解析的域名后缀即可：

```jsonc
{
  "acl": { "mode": "enforce", "default_action": "deny", "groups": [ /* ... */ ] },
  "acl_resolve_domains": ["qunhequnhe.com", "corp.example.com"]
}
```

节点把它编成一条 sing-box 的 `resolve` 路由规则，放在规则链最前。于是内核在路由阶段
就解析出地址，ACL 判定时先按域名匹配，域名一条规则都没命中时改用这些地址再判一轮
（算法见 §3.3）。

| 字段 | 类型 | 必填 | 默认 | 约束 |
|---|---|---|---|---|
| `acl_resolve_domains` | string[] | 否 | `[]` | 域名**后缀**（`qunhequnhe.com` 覆盖 `kaptain.qunhequnhe.com`） |

节点侧会归一化：小写、去空白、剥掉 `+.` / `*.` / 前导点（这些是客户端配置语法，运营常
直接复制过来）、去重、**排序**。不合法的条目被丢弃而不是让整次推送失败 —— 这个字段只
会放宽 `ip_cidrs` 能看到的范围，一条脏数据的代价是匹配不到，不是安全问题。

#### 为什么它必须放在 `acl` 外面

这是**故意的**，不是漏放。`acl` 带 `json:"-"`，刻意不进内核 hash（见 §5 与 `NodeSpec.ACL`
的注释），这样改策略才不会重启 xray、断掉全节点连接。而 `acl_resolve_domains` 会编成
内核路由规则，**必须**进 hash、必须触发内核重建才能生效。

两者的运维语义因此不同，面板 UI 应当分开表达：

| 改动 | 后果 |
|---|---|
| 改 `acl.groups` / `rules` / 用户组成员 | 进程内原子换快照，**不断连**，秒级生效 |
| 改 `acl_resolve_domains` | **重建内核**（xray 是全量重启，会断连），改动频率应当很低 |

把它挪进 `acl` 去"让契约更整齐"会导致改这个字段只在下一次不相关的内核重建时才生效 ——
一个极难排查的静默故障。节点侧有测试钉住这条不变量（`TestKernelHashTracksACLResolveDomains`
与 `TestKernelHashIgnoresACL`）。

#### 上线前必须确认的三件事

- **`private_allow_cidrs` 要先配齐。** `resolve` 是非终止 action（sing-box
  `route/route.go:585`），匹配继续往下走，于是路由层的内网黑名单（`10.0.0.0/8` 等）
  **开始对这些域名生效**了 —— 在此之前域名匹配不上 `ip_cidr`，这类流量是直接落到
  `final: direct` 溜过去的。段没在 `private_allow_cidrs` 里，原本能用的域名访问会在
  **路由层**被 block，而且**不产生任何 ACL 日志**（ACL 根本没被问到），排查方向会完全跑偏。
  这一条本质是收紧 SSRF 防护，方向对，但顺序不能错。
- **节点必须能解析这些域名。** 生成的 sing-box 配置默认没有 `dns` 块，`resolve` 走系统
  解析器。解析失败是连接直接失败，比"被 ACL 拦掉"更难查。节点的 `/etc/resolv.conf`
  指不到内网 DNS 时，要用节点侧 `kernel.custom_config` 补一个 `dns` 块（该字段是整体替换）。
- **只列真正需要的后缀。** 每个后缀给首次连接加一次 DNS（有内核 DNS 缓存兜底）。不要
  为了省事下发一个覆盖一切的后缀。

#### 与 `domain_suffixes` 的取舍

在 ACL 规则里直接写 `domain_suffixes` 也能放行，且不需要内核重建。区别在于安全语义：

- `acl_resolve_domains` + `ip_cidrs`：解析由**节点自己的 DNS** 完成，客户端伪造不了，
  "只放行 10.0.0.0/8"这句话仍然成立；域名哪天指向公网就自然被拒。
- `domain_suffixes`：放行的是这个域名解析到的**任何**地址，包括哪天它指向公网。面板上
  显示的"只放行内网段"与实际生效的语义已经不一致。

#### xray 不支持

xray 的 ACL 钩子在 `Dispatch` 里，比路由更早，session 里没有任何已解析地址。xray 节点
上这个字段无效，节点启动时会打一条 Warn 明说这件事（而不是静默无效），只能改用
`domain_suffixes`。面板若同时管两种内核，UI 应当按节点内核类型给出不同提示。

---

## 4. 校验规范

面板 MUST 在保存时校验并拒绝，**不得把校验推给节点**。节点会再校验一次，但节点的拒绝
方式是"忽略该条 + 日志告警"，运营在面板上看不到，问题会被静默吞掉。

| 字段 | 规则 | 拒绝理由文案建议 |
|---|---|---|
| `ip_cidrs[]` | 必须能被解析为 CIDR，掩码位数合法；IPv4/IPv6 均可 | `非法 CIDR: xxx` |
| `ip_cidrs[]` in `allow` | MUST NOT 含 loopback(`127.0.0.0/8`,`::1/128`)、link-local(`169.254.0.0/16`,`fe80::/10`)、unspecified(`0.0.0.0/32`) | `禁止放行本机/链路本地地址` |
| `ip_cidrs[]` | SHOULD 提示 `0.0.0.0/0` 与 `::/0` 的影响面 | 警告非拒绝 |
| `ports[]` | `^\d+$` 或 `^\d+-\d+$`；范围 1..65535；起 ≤ 止 | `非法端口: xxx` |
| `domains[]` / `domain_suffixes[]` | 不含协议头、路径、空格；不以 `.` 开头；小写归一化 | `非法域名: xxx` |
| `protocols[]` | 仅 `tcp` / `udp` | |
| `action` | 仅 `allow` / `deny` | |
| `groups[].id` | `^[a-z0-9_-]{1,32}$`，同节点内唯一 | |
| 规模 | 单组 CIDR ≤ 20000，单节点全组 CIDR 合计 ≤ 200000 | 超限拒绝并提示拆组 |
| 空规则 | 一条 rule 的所有匹配维度全为空 → 拒绝（等于无条件命中，多半是误操作） | `规则至少需要一个匹配条件` |

节点侧对 loopback / link-local 的过滤逻辑可参照 `internal/kernel/singbox/config.go`
的 `sanitizePrivateAllow`，面板校验保持同样口径。

---

## 5. ETag —— 最容易改不到位的一处

`GET config` 与 `GET user` 都走 `If-None-Match` 协商（`internal/panel/client.go:219,257`）。
节点收到 304 时会**保留上一次的数据**，这是刻意设计（面板抖动时不掉策略），但也意味着：

> **ACL 数据变了而 ETag 没变 = 策略永远不会生效，且没有任何报错。**

常见错误：ETag 只 hash 了 server 表主记录，而 ACL 组/规则/关联在别的表里。

要求：

- config 接口的 ETag MUST 覆盖：节点自身配置 + `acl_mode` + `acl_default_action` +
  该节点可见的全部 ACL 组定义与规则。建议纳入这些表的 `max(updated_at)` 与行数。
- user 接口的 ETag MUST 覆盖每个用户的 `acl_groups` 合并结果。
  仅 hash `v2_user.updated_at` 是不够的 —— 改的是关联表时用户行并不会更新。
- 删除也要反映到 ETag（`max(updated_at)` 对删除无感，需额外计数或版本号）。

推荐做法：单独维护一个 `acl_version` 计数器，任何 ACL 相关写操作 +1，两个 ETag 都把它拼进去。

---

## 6. WS 推送

| 变更 | 推送事件 | 常量位置 |
|---|---|---|
| ACL 组/规则/节点开关 | `sync.config`（带完整 NodeConfig） | `internal/panel/ws.go:20` |
| 用户 ↔ 组 关联变化（大批量） | `sync.users` | `ws.go:21` |
| 少量用户归属变化 | `sync.user.delta` | `ws.go:22` |

- 不需要新增事件类型。
- 面板 MUST NOT 只改 DB 而既不推 WS 也不改 ETag —— 那样策略永不生效。
- 只改 ETag 不推 WS 是可接受的降级：节点会在下一个 `pull_interval` 拉到。
- `sync.user.delta` SHOULD 用于小批量变更：节点收到 delta 时只更新用户映射、复用已编译
  的组策略，不触发全量重编译（全量重编译 5000 用户约 6 ms，50000 约 10 ms）。

---

## 7. mode 三态与灰度

| mode | 节点行为 | 面板要做的 |
|---|---|---|
| `off` | 不判定，零开销 | 默认值，新装节点应为 off |
| `dryrun` | 正常判定，**放行**，把"本应拦截"的连接写入 access log 并上报 | 提供查询视图 |
| `enforce` | 判定并拦截 | 切换时二次确认 |

### 7.1 上报格式

判定结果复用现有 access log 通道 `POST /api/v1/server/UniProxy/accesslog`（`client.go:308`），
**不受 access_log 开关约束** —— 运营开 dryrun 就是为了看影响面，不该被迫同时打开全量访问
日志那个数量级大得多的水管。dryrun 和 enforce 的拒绝都会上报（只报 deny，不报 allow）。

`logs[]` 里的 ACL 记录比普通访问日志多三个字段：

```jsonc
{
  "time": 1700000000000,
  "user_id": 42,
  "source_ip": "203.0.113.9",
  "dest_host": "10.9.0.5",       // 域名目标时是域名
  "dest_port": 443,
  "network": "tcp",
  "upload_bytes": 0,             // ACL 记录产生于连接建立时，恒为 0
  "download_bytes": 0,
  "duration_ms": 0,
  "acl_mode": "dryrun",          // dryrun | enforce
  "acl_action": "deny",
  "acl_rule": "vip#1"            // 组 id + 规则在下发数组里的下标；兜底为 "default"
}
```

- 面板 MUST 按 **`acl_action` 是否存在**来区分两类记录，不要靠 `upload_bytes == 0` 判断。
- `acl_rule` 的下标是**下发数组里的原始位置**，不是按 priority 排序后的位置，这样运营能在
  面板上直接定位到那条规则。隐含 DNS 放行规则的 origin 是 `implicit-dns`。

### 7.2 精确总数与采样

`agent` 对象里多了三个字段，**每轮都上报**（包括没有记录的空轮）：

| 字段 | 含义 |
|---|---|
| `acl_mode` | 节点当前生效的模式 |
| `acl_denials` | **精确**累计拒绝数（自内核启动） |
| `acl_records` | 本轮实际带上来的 ACL 样本条数 |

节点侧的记录缓冲有上限（sing-box 5 万条、xray 2 万条），满了会丢弃并计数，但
**`acl_denials` 是精确的，永远不被采样**。

> 面板 MUST 用 `acl_denials` 算影响面，用 `logs[]` 里的记录看细节。
> 若 `acl_records` 的累计增量显著小于 `acl_denials` 的增量，说明缓冲被打满、
> 细节被截断了 —— 此时按记录条数做的判断会建立在残缺数据上，UI 应当提示。

面板侧要能按「用户 / 组 / 命中规则」聚合，让运营在切 enforce 前看到影响面。

**上线顺序（强制）**：面板先出数据模型与下发（所有节点 `mode: off`，行为无变化）→
节点侧发版 → 逐节点切 `dryrun` 观察数日 → 再切 `enforce`。

---

## 8. 安全护栏（面板 MUST 实现）

`default_action: deny` 会把节点变成"默认不通"。一旦策略不到位就是**全体终端用户断网**。

> **控制通道不受影响。** ACL 只对已认证的代理用户生效（xray 判 `si.User.Email`、
> sing-box 判 `metadata.User`），而 agent 与面板之间用的是自己的 `http.Client`
> 直连，从不流经内核。所以锁死之后面板照样能推配置、能把 `mode` 改回 `off`，
> 健康检查端口和 ACME 签发也都正常。
>
> 唯一的自锁场景是**管理员自己经由该节点访问面板**（面板在内网、靠这条代理进去）——
> 此时切断用户流量会同时切断你进面板的路。属于部署拓扑问题，运维需自行确认是否成立。

因此：

1. 切换节点为 `default_action: deny` MUST 二次确认，并记审计日志（操作人、时间、前后值）。
2. `default_action: deny` 且该节点关联的所有组都没有任何 `allow` 规则 → MUST 阻止保存
   或强提示"这将阻断该节点全部流量"。
3. `implicit_dns_allow` 默认 `true`。若运营关掉它，UI MUST 提示"用户将无法解析域名，
   现象与节点宕机相同"。
4. ACL 编辑权限 SHOULD 独立于普通节点编辑权限。
5. 面板 SHOULD 提供"策略模拟器"：输入 用户 + 目标 IP/域名 + 端口，返回命中的规则与最终
   动作，算法严格按 §3.3。这是运营自查的主要手段。

---

## 9. 验收清单

面板改完后逐条跑。`$P` = 面板地址，`$T` = 节点通信密钥，`$N` = 节点 ID。
GET 请求鉴权走 query（`node_id` / `node_type`）+ `Authorization: Bearer` 头
（`client.go:434,473`）。

```bash
# 通用
CFG="curl -s -H 'Authorization: Bearer $T' '$P/api/v1/server/UniProxy/config?node_id=$N&node_type=vless'"
USR="curl -s -H 'Authorization: Bearer $T' '$P/api/v1/server/UniProxy/user?node_id=$N&node_type=vless'"
```

| # | 检查项 | 操作 | 期望 |
|---|---|---|---|
| 1 | 向后兼容 | ACL 功能整体未启用时取 config | 返回体**不含** `acl` 键，节点行为与改造前一致 |
| 2 | 结构正确 | 建一个组并关联节点后取 config | `acl.mode`/`acl.default_action`/`acl.groups` 齐全，字段名与 §3.1 逐字一致 |
| 3 | **ETag 生效** | 记下 `ETag`；改任一 ACL 规则；带 `If-None-Match` 重取 | 返回 **200**（不是 304），且内容已更新 |
| 4 | ETag 覆盖关联表 | 记下 user 接口 `ETag`；把某用户加入一个组；带 `If-None-Match` 重取 | 返回 **200**，该用户 `acl_groups` 已变 |
| 5 | ETag 覆盖删除 | 记下 ETag；删除一条规则；重取 | 返回 **200** |
| 6 | 用户字段 | 取 user | 每个用户都有 `acl_groups` 键（无组时为 `[]`，不是 `null` 不是缺失） |
| 7 | 合并已完成 | 用户同时通过用户组和单用户 override 关联 | 下发的 `acl_groups` 是**去重后的扁平数组** |
| 8 | 悬空引用 | 删除一个仍被用户引用的组 | 用户的 `acl_groups` 中不再出现该 id |
| 9 | 校验生效 | 尝试保存 `ip_cidrs: ["10.0.0/8"]`、`ports: ["70000"]`、全空 rule | 面板拒绝并给出可读错误，**不下发** |
| 9b | 无 `null` | 关闭 ACL 后取 config；无组用户取 user | 无 `"acl": null`、无 `"acl_groups": null`（见 §10 陷阱 2） |
| 9c | ETag 跨进程一致 | 多 worker 部署下并发取同一 config 若干次 | ETag 恒定；重启面板后仍为同一值（见 §10 陷阱 4） |
| 10 | 危险配置拦截 | 节点设 `default_action: deny` 且无任何 allow 规则 | 阻止保存或强提示 |
| 11 | 二次确认 | 切 `default_action: deny` | 出现确认框 + 审计日志落库 |
| 12 | WS 推送 | 抓节点日志，改一条 ACL 规则 | 秒级看到 `ws recv event=sync.config` |
| 13 | mode=off | 节点 `mode: off` 下跑通全量流量 | 无任何拦截，无性能变化 |
| 14 | dryrun | 切 dryrun，用受限用户访问被禁网段 | 流量**放行**，accesslog 出现带 `acl_action:"deny"` 的记录 |
| 14b | 不依赖 access_log | access_log 关闭状态下重跑 #14 | ACL 记录照常上报（见 §7.1） |
| 14c | 命中规则可定位 | 检查 #14 记录的 `acl_rule` | 形如 `vip#1`，下标对得上你下发数组里的位置 |
| 14d | 精确总数 | 对比 `agent.acl_denials` 增量与实际拒绝次数 | 一致；缓冲打满时 `acl_records` 才会小于它 |
| 15 | enforce | 切 enforce，同上 | 流量被拒；同用户访问放行网段正常 |
| 16 | 组内 AND | 配 `ip_cidrs` + `ports` 同一条 rule | 仅"IP 且 端口"都命中时才生效 |
| 17 | 优先级 | 配互相冲突的两组，调 priority | 结果与 §3.3 首条命中语义一致 |
| 17b | 域名寻址落 default | 只配 `ip_cidrs` 的 allow 规则、`acl_resolve_domains` 为空，用受限用户按**域名**访问该网段 | 判定为 deny，`acl_rule` 是 `default` 或那条兜底 deny —— 这是预期行为，不是 bug（见 §3.5） |
| 17c | 解析回退生效 | 下发 `acl_resolve_domains: ["<该后缀>"]` 后重跑 #17b | 放行，`acl_rule` 指向那条 `ip_cidrs` 规则 |
| 17d | 混合应答不放过 | 让该域名解析出一个段内 + 一个段外地址 | 判定为 deny（任一地址被拒即拒，见 §3.3） |
| 17e | 字段位置正确 | 取 config | `acl_resolve_domains` 与 `acl` **平级**，不在 `acl` 对象里面（见 §3.5） |
| 17f | xray 明确告警 | 给 xray 节点下发 `acl_resolve_domains` | 节点日志出现 `acl_resolve_domains is not supported on this kernel` 的 Warn，而不是静默无效 |
| 18 | 模拟器一致性 | 对 #16 #17 #17b–d 的用例跑面板模拟器 | 输出与节点实际行为逐条一致；模拟器需按内核类型区分是否有解析回退 |
| 19 | 生效时延 | 改组成员后计时 | WS 通道秒级；仅 ETag 时不超过一个 `pull_interval` |
| 20 | 不断连 | enforce 下改组成员 | 其他用户已建立的连接不受影响 |
| 20b | ACL 改动不重建内核 | 改 `acl` 里任意字段（mode / default_action / 规则 / 组），抓节点日志 | xray 出现 `kernel configuration unchanged`、**没有** `performing full restart`；sing-box 不重建 inbound。连接数不掉 |
| 20c | 解析域名改动会重建 | 改 `acl_resolve_domains` | 与 20b 相反：内核重建（xray 全量重启）。这是预期代价，面板 UI MUST 在这个字段上提示，见 §3.5 |

---

## 10. Python 面板实现者必读的四个陷阱

**1. 字段名写错不会报错。**
config 接口在节点侧用 mapstructure 弱类型解码（`client.go:173`，`TagName: "json"`，
`WeaklyTypedInput: true`）。未知字段被静默丢弃，把 `ip_cidrs` 拼成 `ip_cidr` 不会有任何
错误，只会表现为"规则不生效"。**验收 #2 必须逐字比对字段名。**

**2. pydantic / FastAPI 默认会吐 `null`，而 `null` 是被禁止的表达。**
`Optional[X] = None` 的字段序列化后是 `"acl": null`，但 §3.4 规定关闭 ACL 只能用
`mode: "off"` 或整个字段不下发。同理 `acl_groups` 必须是 `[]` 而不是 `null`。

```python
class ACLGroupsMixin(BaseModel):
    acl_groups: list[str] = Field(default_factory=list)   # 不是 Optional[list[str]] = None

# FastAPI 路由
@app.get("/api/v1/server/UniProxy/config", response_model_exclude_none=True)

# 或手动序列化时
cfg.model_dump(exclude_none=True)
```

反过来注意 `implicit_dns_allow`：**它必须能表达"没设置"**。省略该键 = 默认 true；
显式 `false` 才关闭。不要把它默认填成 `False` 下发，否则 deny 模式下用户无法解析域名，
现象与节点宕机完全一样。

**3. user 接口是严格 JSON 解码，错了会掉全部用户。**
`client.go:257` 走标准 `json.Decode`（非弱类型），`acl_groups` 必须是真正的 JSON 数组。
两种常见错法：

```python
# ✗ 数据库 Text 列里存的是字符串，未 json.loads 就直接塞进响应
{"acl_groups": "[\"vip\"]"}        # 节点解析整个 user 列表失败 → 掉全部用户

# ✗ 用 set 去重后忘了转回 list
{"acl_groups": {"vip"}}            # json.dumps 直接抛 TypeError

# ✓
{"acl_groups": sorted(set(groups))}
```

这是本次改造中**唯一会导致节点侧硬故障**的错误，务必覆盖测试。节点侧已固化了这个失败
行为（`internal/panel/acl_test.go` 的 `TestUsersWithStringifiedACLGroupsFailLoudly`）。

**4. 不要用 Python 内置 `hash()` 算 ETag。**
`hash()` 对 str/bytes 加了每进程随机盐（`PYTHONHASHSEED`），后果是：

- 面板每次重启，所有 ETag 都变 → 全部节点被迫全量重拉；
- gunicorn / uvicorn 多 worker 下，同一份数据在不同 worker 算出不同 ETag → 节点在
  200 和 304 之间反复横跳，策略生效时间变得不可预测。

```python
# ✗ etag = str(hash(payload))
# ✓
etag = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"))
                      .encode()).hexdigest()
```

`sort_keys=True` 同样重要 —— dict 顺序变化不该产生新 ETag。

---

## 11. 版本与扩展

- 本文字段名一经发布 MUST NOT 修改或复用。
- 后续扩展只能新增可选字段；节点忽略未知字段，因此面板可以先于节点发布新字段。

节点侧已实现，对应文件：

| 文件 | 职责 |
|---|---|
| `internal/acl/acl.go` | `Policy` / `Store`，匹配与无锁查找 |
| `internal/acl/compile.go` | 配置 → 策略编译、按组 interning |
| `internal/model/acl.go` | 模型类型 |
| `internal/model/acl_validate.go` | §4 校验 |
| `internal/panel/types.go` | 线上协议结构体 |
| `internal/kernel/xray/dispatcher.go` | xray 判定接入点（`checkACL`） |
| `internal/kernel/singbox/conntracker.go` | sing-box 判定接入点（`aclRejects`） |
| `internal/service/service.go` | `refreshACL` 热更新 |

实测（Apple M5，生产 x86 约慢 2–4 倍）：单次判定 **33.0 ns，零分配**；10 核并发 5.4 ns；
5000 用户 / 100 组 / 每组 1000 CIDR 全量重编译 9.6 ms。基准见
`internal/acl/acl_test.go` 的 `BenchmarkCheck` / `BenchmarkUpdate`。
