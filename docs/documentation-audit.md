# 文档与代码不一致清单（documentation-audit）

> 状态：本清单中的条目已在本分支按“确定则修正、不确定则删除”的原则处理；本文保留为 2026-10-30 基线 `d854836` 的审计记录，行号仍指该基线。

基线：`d854836`（2026-10-30）。检查对象：`README.md`、`CLAUDE.md`、`docs/` 下除 `docs/audit/raw/` 外的全部 Markdown（含 `docs/smoke/`、`docs/notes/`）。`examples/switch/` 和 `test/perf/` 的 README/runbook 是开关侧与测试装置文档，只在涉及 FreeSBC 代码行为时抽查，未逐行审计。`go test ./internal/doccheck -run '^TestDocCitations$'` 通过——它只保证“被引用的符号确实声明在被引用的 `.go` 文件里、`.go` 路径能唯一解析、且没有行号”，**不保证语义、默认值、常量、HTTP/指标名称、状态码和文档之间的一致性**。下面列出的都是后者。

每条的格式：位置 → 文档原文（节选）→ 代码事实与证据 → 建议。行号按上述提交，之后会漂移，请按原文定位。

## 总览

| # | 严重度 | 文件 | 问题 |
|---|---|---|---|
| 1 | 高 | `docs/design.md` 第 413、3767、4714 行 | 三处声称“没有 reload 失败指标”，但代码导出了 `freesbc_config_reload_failed` |
| 2 | 高 | `docs/design.md` 第 942 行 | 引用了不存在的指标 `freesbc_edge_responses_total` |
| 3 | 高 | `docs/design.md` 第 3699 行 | “41 个 descriptor”，实际 50 个 |
| 4 | 高 | `docs/design.md` 第 1823–1824 行 | 说 `sanitizeExtensions` 会裁剪 `Supported`，实际只裁剪 `Allow` |
| 5 | 高 | `docs/design.md` 第 3716 行 | 说 `/api/status` 里有 `active_subscriptions`，实际没有 |
| 6 | 高 | `docs/design.md` 第 722 行 | 说 `/api/status` 带 `carrier_requests_total` / `carrier_registrations`，实际没有 |
| 7 | 高 | `docs/design.md` 第 3809 行 | `/api/shield/bans` 的 `reason` 漏了 `malformed`；“Both ban tables”实际是三张表 |
| 8 | 中 | `docs/design.md` 第 3774 行 | 日志示例 `config written via admin API` 在代码里不存在，也没有写 API |
| 9 | 高 | `docs/design.md` 第 1180、2013–2015 行；`docs/edge.md` 第 332 行 | 私网侧无 To-tag NOTIFY 的应答状态描述错误（404/481/405 三种情况） |
| 10 | 高 | `docs/troubleshooting.md` 第 52 行 | “RTCP does not feed it”与代码相反；RTCP 会刷新静音看门狗 |
| 11 | 高 | `docs/smoke/webrtc-dtls.md` 第 52–55 行 | 仍说“FreeSBC 不转发 PRACK、`Require: 100rel` 回 420”，早已支持 |
| 12 | 中 | `docs/design.md` 第 540、586 行 | 两处把拓扑隐藏/`respToCarrier` 指到 §6.5，实际是 §6.6 |
| 13 | 低 | `docs/design.md` 第 3869 行 | 引用不存在的 §13.4a |
| 14 | 中 | `docs/config.md` 第 275 行 | “错误方法一律 405”对 `/api/status`、`/api/calls`、`/metrics` 等不成立 |
| 15 | 低 | `docs/design.md` 第 4715 行；`docs/edge.md` 第 327 行 | “没有 IPv6 测试 / IPv6 未测试”过宽：仓库里有多处 IPv6 单元测试 |
| 16 | 低 | `docs/install.md` 第 17 行 | 依赖列表漏了 `awk` 和 `mktemp`，`install.sh` 会显式检查 |
| 17 | 低 | `CLAUDE.md` 第 15 行 | `hash-password` “任何参数都是 exit 2”不准确：`-h`/`--help` 是 exit 0 |
| 18 | 低 | `docs/edge.md` 第 55 行 | 说被封禁源的 TCP/TLS/WS/WSS 连接会关闭；空闲连接要到下次读取才关闭 |
| 19 | 低 | `docs/design.md` 第 709、719 行 | §6.10 排在 §6.9 之前（编号顺序） |
| 20 | 中 | `docs/config.md` 第 131 行 | 说 switch 节点“在 metrics 里以 `IP:port` 命名”，但没有任何按节点标签的指标 |

---

## 1. 声称没有 reload 失败指标，但指标存在

**位置**：`docs/design.md` 第 413 行（§4.4），第 3767 行（§13.1 末尾），第 4714 行（§16 非目标）。

原文：

- 第 413 行：“There is **no reload-failure metric**.”
- 第 3767 行：“There is no config-reload metric and no carrier DNS metric.”
- 第 4714 行：“- **No reload-failure metric and no carrier DNS metric.**”

**代码事实**：`freesbc_config_reload_failed` 是一个真实导出的 gauge（`internal/admin/metrics.go`，`NewDesc` 在该文件第 104 行；`Collect` 在该文件第 208–216 行按 `Deps.Reload().LastError` 置 0/1）。同一篇 `docs/design.md` 的 §13.1 指标表、§4.4 后半段和 `docs/config.md` 的 “Reload classes” 一节都正确描述了这两个 gauge（`freesbc_config_restart_required`、`freesbc_config_reload_failed`）。所以这三句是三处残留的自相矛盾。

**建议**：删除这三句中的 “no reload-failure metric”。若要保留非目标语义，可改为“只有两个 gauge（`freesbc_config_restart_required`、`freesbc_config_reload_failed`），没有 reload 次数/耗时指标；没有 carrier DNS 指标”。

## 2. 引用了不存在的指标 `freesbc_edge_responses_total`

**位置**：`docs/design.md` 第 942 行。

原文：“These are not INVITE rejects and have no counter of their own (`freesbc_edge_responses_total` sees the 503).”

**代码事实**：没有名为 `freesbc_edge_responses_total` 的指标。响应计数是 `freesbc_sip_responses_total`（`internal/admin/metrics.go` 中 `proxyResOut` 的 `NewDesc`；`internal/edge/metrics.go` 的 `ResponseOut`；本地生成的响应经 `internal/edge/edge.go` 第 1482 行的 `Server.respond` 计数）。`grep freesbc_edge_responses_total` 在整个仓库只命中这一处文档。

**建议**：改为 `freesbc_sip_responses_total`，或删掉指标名只写“本地 503 会进入 `freesbc_sip_responses_total{class="5xx"}`”。

## 3. “41 descriptors”已过时，实际 50 个

**位置**：`docs/design.md` 第 3699 行。

原文：“`Describe` advertises all 41 descriptors of the freesbc collector”。

**代码事实**：`internal/admin/metrics.go` 的 `Describe` 当前发送 50 个 descriptor（18 个逐个 `ch <-`，加列表里的 32 个）；`NewDesc` 也是 50 个。可以用 `grep -c 'prometheus.NewDesc' internal/admin/metrics.go` 复核。文档自己的指标表列出的条目就超过 41。

**建议**：删除具体数字，改为“advertises every descriptor of the freesbc collector”，避免每次加指标都改文档；或写 50。

## 4. `sanitizeExtensions` 不裁剪 `Supported`

**位置**：`docs/design.md` 第 1823–1824 行（§7.8 `prepareForward` 第 3 步）。

原文：“then `sanitizeExtensions` trims `Allow` and `Supported` (§7.3)”。

**代码事实**：`internal/edge/extensions.go` 的 `sanitizeExtensions` 只调用一次 `filterTokenHeader(m, "Allow", ...)`，没有处理 `Supported`；文件头注释也明确写 “Supported, Require, RSeq and RAck pass unchanged”。`docs/design.md` 第 1191–1197 行（§7.3）也正确地说 `Allow` 被裁剪、`Supported` 原样通过。第 1823 行是唯一写错的地方。

**建议**：改为“then `sanitizeExtensions` trims `Allow` (§7.3)”。顺带修 `internal/edge/forward.go` 里同样过时的注释（“Allow and Supported values the proxy cannot carry”），但那是代码注释，不在本次文档范围内。

## 5. `/api/status` 没有 `active_subscriptions`

**位置**：`docs/design.md` 第 3716 行（§13.1 指标表中 `freesbc_edge_subscriptions` 行的末尾）。

原文：“… also `active_subscriptions` in the admin status JSON”。

**代码事实**：`/api/status` 的 JSON 由 `internal/admin/api.go` 第 52–74 行的 `handleStatus` 写出，键只有 `version`、`uptime_seconds`、`active_calls`、`ports`、`listeners`、`listener_info`、`reload`。`ProxyStats` 确实有 `ActiveSubscriptions` 和 `json:"active_subscriptions"` 标签（`internal/admin/server.go` 第 122–126 行），但 `ProxyStats` 只被指标采集器读取，从未被序列化；`active_subscriptions` 不出现在任何 HTTP 响应里（`/api/registrations` 等也不叫这个字段）。

**建议**：删除这半句，或改成“`ProxyStats.ActiveSubscriptions` 只供指标采集使用，不在 `/api/status` 中”。

## 6. `/api/status` 不带 carrier 指标值

**位置**：`docs/design.md` 第 722 行（§6.9）。

原文：“The admin status JSON carries the same two values as `carrier_requests_total` and `carrier_registrations` (`ProxyStats.CarrierRequests` and `ProxyStats.CarrierRegistrations`, `internal/admin/server.go`).”

**代码事实**：同第 5 条：`handleStatus` 的 JSON 没有这两个键；`ProxyStats.CarrierRequests` / `CarrierRegistrations`（`internal/admin/server.go` 第 194、198 行）只被 `internal/admin/metrics.go` 的采集器使用。`/api/carrier-registrations` 返回的是每一条注册明细，不是 `carrier_registrations` 计数；`/api/carriers` 是解析状态。

**建议**：删除“admin status JSON carries …”这句，保留后一句“解析状态和注册明细分别看 `/api/carriers`、`/api/carrier-registrations`”；指标值只从 `/metrics` 读。

## 7. `/api/shield/bans` 的 reason 漏 `malformed`；禁封表不是两张

**位置**：`docs/design.md` 第 3809 行（§13.3）。

原文：“Both ban tables merged, newest first … `reason` is `scanner`, `register` or `admission`”。

**代码事实**：

- `reason` 还有 `malformed`：`internal/shield/banlist.go` 第 28–35 行定义了 `BanReasonScanner`、`BanReasonRegister`、`BanReasonAdmission`、`BanReasonMalformed`；`malformedStrike` 用 `StrikeMalformed` 触发；当越过 `shield.admission_ban` 阈值的那一次是 malformed 时，ban 的 reason 就是 `malformed`（`internal/edge/admission.go` 第 236–251 行；`internal/shield/offenders.go` 第 202–238 行）。`docs/config.md` 的 `/api/shield/bans` 一节和 `docs/edge.md` 的 “Low-and-slow scanners” 都已写对。
- 表有三张，不是两张：IP 表、UDP-only IP 表（`udp_ip`）、UDP socket 表（`udp_socket`）。`internal/shield/shield.go` 第 303–316 行的 `Bans` 合并 `s.bans`、`s.socketBans`、`s.udpBans` 三张表；同节表格列的 `kind` 也正是 `ip`/`udp_ip`/`udp_socket`。

**建议**：改为“All three ban tables merged … `reason` is `scanner`, `register`, `admission` or `malformed`”。

## 8. 不存在的日志 `config written via admin API`

**位置**：`docs/design.md` 第 3774 行（§13.2 `Warn` 行）。

原文：`"config written via admin API"`。

**代码事实**：仓库没有这条日志，也没有配置写入 API。`grep` 该字符串只命中 `docs/design.md`。§13.3 自己写明“The config API is read-only. There is no write endpoint”；`internal/admin/config_validate.go` 也只解析候选文件、不写盘。

**建议**：删除这个日志示例。

## 9. 私网侧无 To-tag NOTIFY 的状态码

**位置**：`docs/design.md` 第 1180 行（§7.3 的 BYE/INFO/NOTIFY 行）与第 2013–2015 行（§7.8）；`docs/edge.md` 第 332 行（Known limitations 的 “NOTIFY is proxied”）。

原文：

- `docs/design.md` 第 1180 行：“An out-of-dialog one from the switch is classified like an out-of-dialog INVITE (§7.5): a client token goes on, a carrier destination → 405, anything else → 404.”
- `docs/design.md` 第 2013–2015 行：“from the switch it is forwarded when the token names a binding FreeSBC holds … and answered 481 otherwise (no target; RFC 6665 §4.1.3)”。
- `docs/edge.md` 第 332 行：“An out-of-dialog NOTIFY (no To tag) from the switch is forwarded when its Request-URI carries the token of a binding FreeSBC holds, and answered 404 otherwise”。

**代码事实**：`internal/edge/indialog.go` 第 445–463 行先做分类，第 486–505 行再决定 481：

- Request-URI（或顶层 Route）带 `fsbc` token、token 没有活绑定 → `classifySwitchRequest` 返回 `targetClient`，`directionFor` 失败 → **481**。测试 `TestOutOfDialogNotify`（`internal/edge/notify_test.go`，子测试 “upstream to unknown binding is 481”）把这个行为固定为 481。
- Request-URI 的 host:port 是 `edge.carriers` 条目 → **405**。
- Request-URI 是 FreeSBC 自己或无法分类 → 分类的 `default` 分支 → **404**。
- token 有活绑定 → 转发。

所以：design 的 §7.8 “481 otherwise”漏了 404 和 405；edge 的 “404 otherwise”漏了 481（未知 token）和 405（carrier URI）；design 的 §7.3 表格漏了“未知 token → 481”。

**建议**：把三处统一成：

> 私网侧无 To-tag 的 NOTIFY：`fsbc` token 有活绑定则转发；token 未知/过期 481；Request-URI 是 carrier 条目 405；FreeSBC 自己或无法分类 404。

## 10. RTCP 会喂静音看门狗

**位置**：`docs/troubleshooting.md` 第 52 行。

原文：“Only a packet the first-packet latch accepted refreshes it: a packet from a source that does not match the latch, and an SRTP packet that fails authentication, never do. RTCP does not feed it.”

**代码事实**：`internal/media/relay.go` 的四个 relay 循环共用同一段代码：无论 `rtpKind` 是 true（RTP）还是 false（RTCP），只要 latch 接受（SDES 侧还要解密成功），就在第 90 行执行 `s.lastRx[from].Store(time.Now().UnixNano())`；`watchdog` 只看 `lastRx`。文件第 126–129 行的注释也写明 “Both RTP and RTCP count, so a receive-only side that sends RTCP receiver reports stays alive.” `docs/design.md` §8.5 同样正确地说 “RTP and RTCP both count”。只有这一句 troubleshooting 是反的。

**建议**：删掉 “RTCP does not feed it.”，改为“RTCP 也会刷新；只有 latch/认证失败的包不刷新”。如果原意是“RTCP 不计入 `freesbc_rtp_*` 统计”，那是另一件事（`internal/media/stats.go` 的 `recordRx` 对 `rtp == false` 直接返回），可以改写为“RTCP 会刷新看门狗，但不计入 RTP 包/字节指标”。

## 11. smoke 手册仍称不支持 PRACK / 100rel 回 420

**位置**：`docs/smoke/webrtc-dtls.md` 第 52–55 行。

原文：“Leave reliable provisionals (100rel) unsupported or supported, never *required*: FreeSBC does not relay PRACK, so an INVITE with `Require: 100rel` is answered `420 Bad Extension` (sip.js: keep `sipExtension100rel` at its default, not `Required`).”

**代码事实**：PRACK 已实现并注册：`internal/edge/edge.go` 第 672–673 行注册 `OnPrack` / `OnUpdate`，处理函数是 `internal/edge/prack.go`；`internal/edge/extensions.go` 第 19 行明确写 “Supported, Require, RSeq and RAck pass unchanged”；`allowedMethods` 包含 PRACK。代码里没有发送 420 的路径（`grep 420` 在非测试代码里无命中）。`docs/edge.md` 第 295–302 行、`docs/design.md` §7.9a 都已描述支持。该段写于 2026-09-26，而 PRACK 支持在 2026-10-07 的提交里加入，之后没有更新这份 smoke 文档。

**建议**：删除 “never required / 420 Bad Extension” 的说法，改成：“100rel 可以设为 required；PRACK 会被转发，PRACK 携带 SDP 只作为延迟 offer 的 answer 接受（其他情况 488），详见 `docs/edge.md` 的‘Reliable provisionals, UPDATE and delayed offers’。”

## 12. 两处 §6.5 交叉引用错误

**位置**：`docs/design.md` 第 540 行、第 586 行。

原文：

- 第 540 行：“What differs from the client path is topology hiding (§6.5)”。
- 第 586 行：“Responses go back through `respToCarrier` (§6.5)”。

**代码/文档事实**：§6.5 是 “Outbound path: switch to carrier”；拓扑隐藏和 `respToCarrier` 在 §6.6 “Topology hiding”（其中 “Response to the carrier” 段落描述 `respToCarrier`）。同篇文档第 1847、1855、2110、4386、4669 行都正确引用 §6.6。

**建议**：两处改为 §6.6。

## 13. 不存在的 §13.4a

**位置**：`docs/design.md` 第 3869 行。

原文：“A **valid session cookie** (`freesbc_session`, §13.4a) serves the request …”

**事实**：`docs/design.md` 有 §13.4 “Authentication and its limiter”，其内部有 “Login endpoint and sessions” 段，但没有 §13.4a 标题。全文没有其他 §13.4a。

**建议**：改为 §13.4（Login endpoint and sessions 段），或给会话部分加 §13.4a 标题。

## 14. “错误方法一律 405”对部分路由不成立

**位置**：`docs/config.md` 第 275 行。

原文：“A wrong method is `405` with an `Allow` header.”

**代码事实**：只有显式检查 method 的 handler 才返回 405。`/healthz`（`internal/admin/server.go` 第 718–721 行）、`/`（`handleUI` 的 catch-all）以及 `/api/status`、`/api/calls`（`internal/admin/api.go` 第 52–94 行）都不检查 method，POST/PUT 等也会被处理；`/metrics` 交给 Prometheus 的 handler。`docs/design.md` §13.3 的表格把这些路由的方法列成 “any”，是正确的；`docs/config.md` 的这句总述过宽。

**建议**：改为“对声明了方法的路由，错误方法返回 405 + `Allow`；`/api/status`、`/api/calls`、`/metrics` 和 WebUI 路由接受任意方法（见 design.md §13.3 的 Methods 列）”。

## 15. “没有 IPv6 测试 / IPv6 未测试”过宽

**位置**：`docs/design.md` 第 4715 行；`docs/edge.md` 第 327 行。

原文：“there are no IPv6 tests.” / “**IPv6 is untested**, though the code paths are address-family agnostic.”

**事实**：仓库里有多处 IPv6 单元测试，例如：

- `internal/shield/ratelimit_test.go`（`2001:db8:…` 的 /64 桶）
- `internal/shield/offenders_test.go`（IPv6 /64 strike 合并）
- `internal/config/config_test.go`（IPv6 carrier、`allowed_hosts`、`host:port` 解析）
- `internal/admin/guard_test.go`、`internal/admin/limiter_test.go`、`internal/app/health_test.go`（`[::1]` Host / IPv6 回环 admin）
- `internal/edge/stream_test.go`、`internal/edge/admission_test.go`、`internal/sip/regscan_test.go` 等也有 IPv6 地址用例

准确的说法是“没有端到端 IPv6 SIP/媒体部署测试”，而不是“没有 IPv6 测试”。

**建议**：两处都改成“IPv6 没有端到端部署测试（单元测试覆盖了地址族处理）”。

## 16. `install.sh` 的依赖列表漏了 `awk` 和 `mktemp`

**位置**：`docs/install.md` 第 17 行。

原文：“It needs `curl` or `wget`, `tar`, and `sha256sum` or `shasum`”。

**代码事实**：`install.sh` 在 `main` 里显式执行 `need tar`、`need awk`、`need mktemp`；`verify` 用 `awk` 抽取 `SHA256SUMS` 中的一行，`main` 用 `mktemp -d` 建临时目录。脚本还使用 `install`、`cmp`、`sed`、`grep` 等常用工具。

**建议**：补上 `awk` 和 `mktemp`：“It needs `curl` or `wget`, `tar`, `awk`, `mktemp`, and `sha256sum` or `shasum`”。

## 17. `hash-password` 并非“任何参数都 exit 2”

**位置**：`CLAUDE.md` 第 15 行。

原文：“`freesbc hash-password` (no `-c`, no arguments: any argument is exit 2)”。

**代码事实**：`cmd/freesbc/hashpassword.go` 对 `-h`/`--help` 打印 usage 并返回 0；只有其他参数返回 2。`docs/design.md` §4.1 的表格已经正确写成“any argument but `-h`/`--help` is a usage error”。

**建议**：改为“any argument other than `-h`/`--help` is exit 2”。

## 18. 被封禁的流连接不是“立刻关闭”

**位置**：`docs/edge.md` 第 55 行。

原文：“A source the shield has banned gets no response at all: it is dropped before parsing, and its TCP/TLS/WS/WSS connection is closed.”

**代码事实**：`guard` 只关闭触发封禁的那条连接；read filter 对同一源的其它连接在**下一次读取**时关闭（`internal/edge/edge.go` 的 `closeStream` 调用点和 `internal/edge/stream.go` 的读循环）。`docs/design.md` 第 4249 行正确地说“An idle connection opened before the ban stays open until it next sends.”

**建议**：改为“触发封禁的连接立即关闭，同源其它流连接在下一次读取时关闭；空闲连接会保留到下一次发送”。

## 19. §6.10 排在 §6.9 之前

**位置**：`docs/design.md` 第 709 行（§6.10）与第 719 行（§6.9）。

**事实**：章节编号顺序反了。多数引用按标题而非编号，因此不会断链，但读者按编号跳转时会先看到 §6.10。

**建议**：交换两个标题（并把 §6.9 的内容放到 §6.10 前），或把 “Stream transports to and from carriers” 改成 §6.9、“Observability and admin” 改成 §6.10。交换编号后要全文替换对 §6.9/§6.10 的引用。

## 20. switch 节点并不出现在指标标签里

**位置**：`docs/config.md` 第 131 行（`edge.switch`）。

原文：“A node is named by its `IP:port` in logs and metrics.”

**代码事实**：日志里确实用节点名（`internal/edge/register.go` 的 `registerUnanswered`、`cooldown.go` 的 WARN），IP:port 也出现在 `/api/switch-nodes`（`internal/admin/state.go` 第 246–260 行）；但没有任何指标带 switch 节点标签。`freesbc_edge_register_unanswered_total` 和 `freesbc_edge_register_breaker_rejects_total` 都是无标签计数器（`internal/admin/metrics.go` 第 116–117 行；`docs/design.md` §13.1 也明确写 “no node label”）。按节点做的健康状态只能从 `/api/switch-nodes` 或日志看，Prometheus 侧没有 node 维度。

**建议**：改为“A node is named by its `IP:port` in logs and in `/api/switch-nodes`”；如果要给 Prometheus 节点维度，那是新增指标，不是现状。

---

## 跨文档矛盾（同一事实两种说法）

| 事实 | 正确说法（代码） | 错误/过时的文档 |
|---|---|---|
| 是否存在 reload 失败指标 | 有：`freesbc_config_reload_failed` | `docs/design.md` 413、3767、4714 行说没有；同篇 §4.4 末尾、§13.1 和 `docs/config.md` 说有 |
| 私网侧无 To-tag NOTIFY 的应答 | 活 token 转发；未知 token 481；carrier URI 405；其它 404 | `docs/design.md` 2014 行说 481 otherwise；`docs/edge.md` 332 行说 404 otherwise |
| RTCP 是否刷新静音看门狗 | 刷新（`internal/media/relay.go`） | `docs/troubleshooting.md` 52 行说“不刷新”；`docs/design.md` §8.5 说刷新 |
| `/api/status` 的内容 | 只有 version/uptime/active_calls/ports/listeners/listener_info/reload | `docs/design.md` 722、3716 行说还带 carrier 计数和 active_subscriptions；同篇 §13.3 的 `/api/status` 行没有这些字段 |
| 封禁后流连接何时关闭 | 触发连接立即关闭，其它连接下次读取时关闭，空闲连接保留到下次发送 | `docs/edge.md` 55 行说连接关闭；`docs/design.md` 4249 行说空闲连接保留 |
| 100rel/PRACK | 支持并转发，`Require` 原样通过 | `docs/smoke/webrtc-dtls.md` 52–55 行说不支持、回 420；`docs/edge.md` 和 `docs/design.md` 说支持 |

## 已逐项核对、与代码一致的部分

下面这些是本次逐文件核对过的“高风险点”，未发现不一致（列出来是为了说明检查范围和给后续维护一个回归清单；不是全文清单）：

- `docs/config.md`：加载顺序（严格 YAML → `${VAR}` → 默认值 → `validate`）；`rtp` 的 1024/`min < max`/偶数对容量公式；`public.bind` 默认与 NAT 清单文本；`edge.listen` 与 `edge.advertise` 的端口/冲突规则；`edge.carriers` 的 host/port/transport/`srtp`/`ca_file`/`client_cert` 规则与重复检测；`edge.carrier_sources` 的 `/8`、`/32` 宽度上限；`shield.*` 的默认值（`20/s per_ip`、`200/s per_ip`、`1h`、`10/10m`、`50/5m`、`max_sessions`）、语法与 hot 分类；`admin` 的 loopback/`allow_remote`/bcrypt cost/`allowed_hosts`/`pprof`；`/api/*` 路由、Host/Origin 检查、session 常量（30 min / 12 h / 8 个 / 1 h `verifiedCreds`；`verifiedCreds` 的 16 条上限见 design.md 与代码）；`hep` 的字段与 TLS 规则（4096 包队列见 homer.md）；常量表（`PrivateSIPPort`、`DefaultCarrierPort`/`DefaultCarrierTLSPort`、5 s/10 s/5 min/30 s/32 s、DNS 300/10/3 s、`AdminUser`）；reload 分类表与 `restartOnly` 一致。
- `docs/design.md`：§15.2 全部超时值（逐个对照常量）；§7.1a 的 256/10000/1024/10 s/15 s/60 s/10 s 和 24 KiB；§13.4 的 auth limiter（10/min、4096 源、/64）、session 常量；§13.5 的 256 条 audit ring；§13.6 的 90%/100%、3 次/10 min、60 s、30 天、200 条 health ring；§14.1 的 4096/16384/384/64/65536/20000/10/32/64/1024/11 个 scanner 签名；§8.7 的 1508 字节、64 KiB/1 MiB mux 缓冲、3 字节/18 字节 ICE 凭据、30 s 建立；§8.8 的 16 KiB/16/256/128 限制和 `126<<24|65535<<8|255` 优先级；§6.8 的 token = base32(sha256(node+"\n"+contact)) 截 26 字符；§7.4 的 20000/10、enum 10/10 min/4096；§7.7 的 32 个 provisional、4096 个 linger、8 s `ack2xxDrainWait`；§13.1 的指标表（除第 5、6 条的错误字段；descriptor 计数见第 3 条；其余名称、标签集合与 `Describe`/`Collect` 一致）；§13.3 的 API 形态（除第 5、6、7 条）。
- `docs/edge.md`：drain 的四方向矩阵；admission 各类 drop 与 481/404/405 的选择（NOTIFY 除外，见第 9 条）；REGISTER 枚举、credential guard、per-AoR lock 的默认值与豁免；MESSAGE 1300 字节；SUBSCRIBE 32/20000/`Retry-After`；carrier 分类、Contact 重写、token 恢复、TLS 校验、`;alias`；流常量；SDES 三种策略；100rel/UPDATE/延迟 offer 的描述；UDP 缓冲区 8 MiB/1 MiB。
- `docs/troubleshooting.md`：`call ended` 的 11 个 reason 和 `terminated_by`；`ack_missed` 阈值；RTP 静音 5 min 与 `timeout/4` 轮询；8 MiB 缓冲区与 `freesbc_udp_socket_*`（仅第 10 条的 RTCP 句错误）。
- `docs/admin-ui.md`：tokens.css 的三段结构、`green-700/400`、`amber`、`blue-600/400`、`red-600/400`；`light-dark()`；CSP；未认证资源恰好是 `login.html`、`login.js`、`tokens.css`、`ui.css`、`theme.js`；diff 的 `add/del/ctx/skip/note`；meter 80%/95%；300 ms 搜索防抖、50 条分页；`TestUITokenContrast`、`TestUIColoursComeFromTokens`、`TestUIHasNoInlineScriptOrStyle` 均存在并通过。
- `docs/homer.md`：HEP chunk `0x02/0x03/0x04/0x05/0x06/0x07/0x08/0x0b/0x0c/0x11/0x13`、17/6 协议号、4096 队列、`REDACTED`、镜像在 `marker.stamp` 之前、tcp/tls 重连退避。
- `docs/install.md`、`install.sh`、`packaging/freesbc.service`：`FREESBC_VERSION`/`PREFIX`/`BASE_URL`/`VERIFY`、`--no-service`/`--dry-run`、`0755` 二进制安装、`0750 root:freesbc` 配置目录、`0640` 配置、unit 的 `ExecStart`/`RestartSec=5s`/`LimitNOFILE=65536`/`CAP_NET_BIND_SERVICE`、`init` 的 6 个提示顺序与权限 0600、`check --deploy` 打开的 TLS 文件集合。
- `docs/two-node.md`：`${VAR}` 用法、`CheckLocalAddr`、drain 下的 carrier/agent 行为、重启后 404 的 stale Contact、注册间隔窗口、媒体超时。
- `docs/notes/170-sipgo-tx-linger.md`：`serveTx` 已删除、`TerminateGracefully` 行为、`ack2xxDrainWait` 8 s、`TestServerTxDoesNotParkGoroutines`，与当前代码一致（该文件不在 doccheck 范围内）。
- `README.md` / `CLAUDE.md`：构建命令、release/CI/install/soak 的 workflow 结构、go.mod 的 Go 版本、包依赖方向、测试端口段（app 10000–10099、admin 10100–10199、media 20000–24999、edge 25000–27999/28000–32399）、`doccheck` 的覆盖范围、`hash-password` 的 bcrypt cost 和 stdin 行为（`-h` 的口径见第 17 条）。

## 无法由本仓库代码验证的文档内容

以下不属于“文档与代码不一致”，本次没有当作错误，但维护时要注意它们会独立过期：

- `docs/performance.md` 和 README 里的性能数字（5000 calls、3500 CPS、8 h soak、19k 注册、GOMEMLIMIT 等）：它们绑定某次三主机运行和 v0.5.0，代码只能验证“测量方法/常量”（例如 8 MiB 缓冲区、`shield.max_sessions` 默认值），不能验证数字。
- 对 FreeSWITCH、Asterisk、HOMER 11、heplify、cosign 行为的描述（例如 sofia 的 `register-proxy`、Asterisk `line=yes`、HOMER 忽略 HEP auth key）：这些是外部软件行为，只能在对应版本上复测。
- `docs/two-node.md` 里标为 “not exercised” 的项、`docs/smoke/webrtc-dtls.md` 的浏览器/FreeSWITCH 手工步骤：它们是测试记录，不是代码契约。
- Release 历史（哪个版本开始有 `install.sh`/`SHA256SUMS.sigstore.json`、`LAST_UNSIGNED` 的值）：由 GitHub Release 状态决定，仓库内只能验证 workflow 的当前配置。

## 建议的修改顺序

1. 先改第 1、2、3、4、5、6、7、8、9、10、11 条（会让读者相信错误的行为/接口/指标，或按错误状态码排障）。
2. 再改第 12、13、14、18、20 条（交叉引用、方法/连接语义和指标维度）。
3. 最后改第 15、16、17、19 条（措辞和顺序）。

改完后跑 `go test ./internal/doccheck -run '^TestDocCitations$' -count=1`：本文件也在 doccheck 的扫描范围内，新增的 `.go` 路径引用必须能唯一解析，且不能引入 `file.go:行号` 形式。
