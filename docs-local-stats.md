# 本机统计接口（只读，默认关闭）

给运行节点的设备本身（比如路由器上的管理页面）看实时统计用。**默认关闭**；设了环境变量才开：

```sh
LB_NODE_STATS_LISTEN=127.0.0.1:65532 xboard-node -c config.yml
```

- 只允许回环地址（`127.0.0.0/8`、`::1`、`localhost`），填其它地址会拒绝并在日志里提示，节点照常运行。
- 端口被占用时同样只是提示，不影响节点。
- 关闭时不注册、不采样，行为和上游完全一样。
- 数据每 10 秒采样一次并缓存，请求只读缓存，不会碰到内核和各节点服务。

## GET /stats（JSON）

| 字段 | 说明 |
|---|---|
| `version` / `now` / `sampled` / `started` / `interval` | 版本、当前时间、最近一次采样时间（0 = 还没采样）、进程启动时间、采样间隔（秒） |
| `machines[]` | 机器模式：`id`、`panel`（只有主机名）、`ws`（-1 不用 WS / 0 断开 / 1 已连接）、`discovery` / `status`（拉节点列表 / 上报机器状态的结果，见下面 ConnSnapshot） |
| `nodes[]` | 每个节点：`id name type protocol port kernel`、`state`（running / starting / retrying）、`started`、`users`（面板下发的用户数）、`online_users online_ips conns up_bps down_bps`、`access_log`（面板是否开了访问日志）、`dial`（最近 10 分钟出站拨号 `total` / `fails`，仅 sing-box）、`ws`、`pull` / `push`（同步配置 / 上报流量的结果）、`retry`（启动失败：`attempts next error at`） |
| `total` | 合计：`online_users online_ips conns up_bps down_bps` |
| `users[]` | 有流量或在线的用户（按当前速率排序，最多 500，`users_active` 是总数）：`id uuid`（前 8 位）、`up_bps down_bps`、`up down`（节点服务启动以来的字节数）、`ip_count ips`（最多 32 个）、`conns`、`device_limit`、`nodes`、`rejects`（最近 10 分钟被设备数限制拒绝的连接数） |
| `history` | 最近 15 分钟，每 10 秒一点：`[时间, 上行 B/s, 下行 B/s, 连接数, 在线用户, 在线 IP]` |
| `access` | 访问目标聚合（面板开了访问日志才有数据）：`enabled since records`、`by_bytes` / `by_count`（各前 30：`host bytes up down count fails`） |
| `alerts[]` | 异常：`kind`（shared / surge / dial）、`user` 或 `node`、`value`、`limit`、`rejects`、`since` |

ConnSnapshot：`last_ok last_fail`（unix 秒，0 = 从未）、`last_error`、`fails`（自上次成功以来连续失败次数）、`fail_since`（这一轮连续失败从什么时候开始）、`fails_total`。

异常判定：

- **shared**（疑似共享账号）：在线 IP 数连续 3 次采样超过设备数上限，或最近 10 分钟有 ≥ 5 个连接被设备数限制拒绝。
- **surge**（流量突增）：用户 5 分钟平均速率 ≥ 4 MiB/s 且是 1 小时基线的 5 倍以上（新出现的用户先观察 5 分钟）；回落到基线 3 倍以内或 2 MiB/s 以下解除。
- **dial**（出站拨号失败多）：节点最近 10 分钟拨号失败 ≥ 30 次且占 ≥ 20%。

## GET /stats/user?id=<用户 ID>

`ips`（当前来源 IP）、`rejected_ips`（最近被设备数限制拒绝的来源 IP）、`device_limit`、`access_log`、`since`、`hosts`（这个用户访问最多的 50 个目标）。

## GET /stats/counters（纯文本，给 shell 脚本定时采样）

```
t <当前时间> <进程启动时间>
n <节点> <计数起点> <运行中 0|1> <上行 B/s> <下行 B/s> <连接数> <在线用户> <在线 IP>
u <节点> <计数起点> <用户> <上行字节> <下行字节>
a <类型> <用户|节点> <值> <上限> <开始时间>
c <调用> <节点|机器> <连续失败> <这轮开始> <最近失败> <最近成功> <超时 0|1>
```

`c` 行是对面板的调用：节点的 `pull`（同步配置）/ `push`（上报流量），机器的 `discovery`（拉节点列表）/ `status`（上报状态）。日志里连续失败只打第一次和每 10 分钟一条汇总，这里每次都计数——路由器插件的「断连自动恢复」按它判断。

`u` 行是从 `<计数起点>`（该节点服务启动的 unix 秒）累计的字节数；计数起点变了表示从零重新计。

## 日志

周期性的调用（同步配置、上报流量、上报访问日志、拉节点列表、上报机器状态、WS 重连）不再每次都打日志：

- 成功：不打（`report pushed` 降为 DEBUG）
- 连续失败：第一次打 WARN（`<调用> failed`，带原因），之后每 10 分钟最多一条 WARN 汇总（`<调用> still failing failures=… for=…`），其余为 DEBUG
- 恢复：打一条 INFO（`<调用> recovered failures=… after=…`）

启动、节点启动 / 停止 / 重试、证书、配置变化等状态变化照常是 INFO。

## 内存与开销

- 访问目标只保留聚合（不保留单条记录），两代各 12 小时轮换，每代最多 2048 个目标、500 个用户 × 40 个目标；超出时丢掉较小的一半。
- 给面板的访问日志推送不受影响：聚合只读取同一批记录，不修改、不截留。
- 每个用户的累计流量是一张 map，每 10 秒复制一次（只在开启时）。
