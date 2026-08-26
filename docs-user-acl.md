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

| 字段 | 类型 | 必填 | 默认 | 约束 |
|------|------|------|------|------|
| `acl` | object | 否 | **缺失 = ACL 完全禁用** | 见 §3.4 |
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

check(user, dest_ip, dest_domain, port, proto):
    for r in policy_of(user).rules:
        if matches(r, ...): return r.action        # 第一条命中即决定
    return policy_of(user).default_action
```

要点：
- **首条命中即返回**，不做"deny 优先"之类的隐式覆盖。顺序完全由 priority 决定。
- 组级 `default_action` 取**优先级最高的那个非 null 组**的值；都为 null 则用节点级。
- 目标是域名时只走域名维度，是 IP 时只走 IP 维度。**节点不会为了匹配 IP 规则去解析域名**
  —— 每连接一次 DNS 会比 ~30 ns 的匹配贵五个数量级。因此需要按域名放行的场景，
  面板 UI MUST 引导运营同时配 `domain_suffixes`，不能只配 `ip_cidrs`。

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

dryrun 上报复用现有 access log 通道 `POST /api/v1/server/UniProxy/accesslog`
（`client.go:308`），记录里增加 ACL 判定结果字段。面板侧要能按"用户 / 组 / 命中规则"
聚合，让运营在切 enforce 前看到影响面。

**上线顺序（强制）**：面板先出数据模型与下发（所有节点 `mode: off`，行为无变化）→
节点侧发版 → 逐节点切 `dryrun` 观察数日 → 再切 `enforce`。

---

## 8. 安全护栏（面板 MUST 实现）

`default_action: deny` 会把节点变成"默认不通"。一旦策略不到位就是全员断网，**且运营
无法通过面板自救**（用户连不上，管理员自己也连不上）。因此：

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
| 14 | dryrun | 切 dryrun，用受限用户访问被禁网段 | 流量**放行**，面板 access log 出现"本应拦截"记录 |
| 15 | enforce | 切 enforce，同上 | 流量被拒；同用户访问放行网段正常 |
| 16 | 组内 AND | 配 `ip_cidrs` + `ports` 同一条 rule | 仅"IP 且 端口"都命中时才生效 |
| 17 | 优先级 | 配互相冲突的两组，调 priority | 结果与 §3.3 首条命中语义一致 |
| 18 | 模拟器一致性 | 对 #16 #17 的用例跑面板模拟器 | 输出与节点实际行为逐条一致 |
| 19 | 生效时延 | 改组成员后计时 | WS 通道秒级；仅 ETag 时不超过一个 `pull_interval` |
| 20 | 不断连 | enforce 下改组成员 | 其他用户已建立的连接不受影响 |

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
