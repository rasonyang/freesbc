# FreeSBC 整改任务清单（REMEDIATION-PLAN）

## 1. 基线

- 生成时间：2026-08-26
- HEAD：`b998f0883c363f4890f950f576d9de99d52c5630`（与审计时同一 commit，代码未变）
- 工作区：`git status --short` 仅 `?? docs/SECURITY-AUDIT-20260826.md`（审计报告）与本文件，无生产代码改动
- 输入报告：`docs/SECURITY-AUDIT-20260826.md`（F-01…F-21 + 28 条 Low/纵深/待验证）
- 复核方式：全部发现在当前 HEAD 用 Read/Grep 重新定位（本机无 Go 工具链，复核为源码级；涉及 sipgo 的证据对照 go.sum 锁定的 v1.4.3 源码）
- 驳回率：2/50 ≈ 4%（未超三成，原报告可靠性无系统性问题）

## 2. 复核汇总表

图例：✅=已复核（立项）｜🅿=挂起｜❌=驳回｜⊕=并入（修复动作与某任务同源，不另立卡）

| 发现 | 结论 | 一行理由（本次重新定位的证据） |
|------|------|------|
| F-01 | ✅ | sipgo transport_udp.go:177-184 对每个新远端 `pool.Add`，先于解析；sig/server.go:324-358 无 readFilter |
| F-02 | ✅ | sig/server.go:328-345 裸 Listen；sipgo parser_stream.go Write 无条件累积、partial 被忽略 |
| F-03 | ✅ | shield/shield.go:81-86 scanner ban 先于 :87-92 限速；banlist.go:26-33 锁外同步 nft exec |
| F-04 | ✅ | shield/nftables.go:62-63 规则无 dport 限定；admin/server.go:63-75 无 unban 路由 |
| F-05 | ✅ | shield/banlist.go:13-22 map 无上限，prune(:60-69) 只清过期 |
| F-06 | ✅ | sig/b2bua.go:276-286 INVITE 即分配 2 对端口；media/portpool.go:54-84 无 per-peer 配额；schema 无 max_calls 字段 |
| F-07 | 🅿 | 发现成立（sig/identify.go:17-30 仅源 IP），但修复=入向 digest/mTLS 是新产品能力，需产品决策定义期望行为，写不出针对现有代码的失败测试 |
| F-08 | ✅ | sig/b2bua.go:127-151 仅 To-tag 存在性 + Call-ID 查表（callsdp.go:67-72），无比对 From/To tag |
| F-09 | ✅ | media/srtp.go:52 CreateContext 无选项；srtp_relay_test.go:10-13 仓库自认 no-replay |
| F-10 | ✅ | sipgo transaction_layer.go:214-226 事务层 400、:18-20 杂散 response Info 日志、transport_udp.go:229 全字节日志，均不经 handler |
| F-11 | ✅ | sig/sdp.go:176-190 relay 段保留除 crypto/rtcp 外全部属性（declined 段 :198-200 才清空） |
| F-12 | ✅ | sig/b2bua.go:1089-1103 buildFrom 原样透传 DisplayName/User；routing.go:44-50 无 match 时号码原样透传 |
| F-13 | ✅ | sig/tlscert.go:21-54 恒自签且无证书配置字段；schema.go 全文无 tls_cert 类字段 |
| F-14 | ✅ | admin/server.go:102-105 无条件 bcrypt（含无 Authorization 头）；无失败限速 |
| F-15 | ✅ | main.go:104,127 启动期固化 admin cfg；admin/server.go:59,103-104 每请求用旧凭据（store.Replace 存在但 admin 不读） |
| F-16 | ✅ | config/validate.go:98-106 无宽度/非空检查（0.0.0.0/0 通过）；parsePrefixOrAddr(:257-266) 不 Masked |
| F-17 | ✅ | sig/server.go:391-401 sourceAddr 无 Unmap（全仓 Unmap 仅 media/session.go:82） |
| F-18 | ✅ | admin/config_write.go:64-79 仅设 Content-Type+ETag；admin 包无任何 Cache-Control |
| F-19 | ✅ | shield/shield.go:74-76 peer 直接 Allow，无限速路径 |
| F-20 | ✅ | sig/register.go:~101 DoDigestAuth 直接用远端 realm/nonce，无钉扎字段（PeerAuth 仅 Username/Password，schema.go:75-78） |
| F-21 | 🅿 | 发现成立，但 A/AAAA 解析发生在 sipgo 发送时（resolve.go 只出主机名端点，:71,99），仓库层无可实现的告警观测点；pinning 配置与 T-17 重叠——T-17 落地后重估 |
| D1-8 | ✅ | sig/server.go:488-582 四个 handler 无 recover；b2bua.go:127 缺 To 头即 nil-deref（靠 :81 recoverCall 兜住且无 400） |
| D3-2 | ✅ | admin 全部响应无 nosniff/CSP/XFO（server.go:63-75 + recoverMW :115-132 无头注入） |
| D3-4 | ✅ | admin/server.go:80 仅 ReadHeaderTimeout（无 Idle/Read/WriteTimeout、无连接上限） |
| D3-5 | 🅿 | 前提（Call-ID 无长度限制）成立，但影响上限未证实；T-01 前置过滤落地后攻击面收缩，再评估是否立项 |
| D4-2 | 🅿 | 机制已在 goccy v1.19.2 上游源码核验（BytesUnmarshaler 路径 formatAlias 无界），但崩溃复现需 Go 环境运行 PoC——红测试无法在本机确认当前 FAIL |
| D4-3 | ✅ | admin/config_write.go:113-116 继承原文件 Perm（0644 保留） |
| D4-4 | 🅿 | TOCTOU 窗口属实（config_write.go:97-117 无锁），但「并发 PUT 一方 409」的断言依赖竞态时序，写不出确定性红测试；需先定串行化设计 |
| D4-5 | ✅ | writeFileAtomic 无目录 fsync；:52 os.Rename 对 symlink 是替换链接本身（os 语义，代码无 Lstat 检查） |
| D4-6 | ✅ | validate.go:167-170 非 loopback admin.listen 静默通过；:174-176 bcrypt.Cost 无下限 |
| D4-7 | ✅ | config/loader.go:11-17 os.ReadFile 整读无上限（对照 config_write.go:59 有 1MiB） |
| D4-8 | 🅿 | reload.go:57-59 `!ok → return nil` 属实，但触发条件（fsnotify Events 通道非 Close 关闭）测试不可注入——需重构暴露注入点 |
| D5-3 | 🅿 | 属实（media/session.go:77-84 pre-latch 只比 IP），修复（SSRC 预学习/文档）是设计取舍，需产品决策 |
| D5-4 | ✅ | media/relay.go:45 lastRx 在 :50-60 unprotect 之前刷新 |
| D5-7 | 🅿 | 属实（relay.go:28-33,72-74 RTCP 透传），剥/重写 CNAME 是可选加固，需互操作决策 |
| D6-8 | ⊕ | 报告已并入 F-06（无 max_calls），由 T-06 承接 |
| D6-9 | ✅ | callstate/registry.go:28-32 Add 覆盖同 ID；b2bua.go:303-327 三表均裸 Call-ID 键 |
| D7-5 | ⊕ | 「shield 在 handler 层」的可行动修复=readFilter 前置过滤，与 F-01 完全同源，由 T-01 承接（独立立卡会重复同一测试） |
| D7-6 | ✅ | shield/shield.go:26-47 nftables 模式构造期固定（注释自认），Replace 后不重建 backend |
| D7-7 | ✅ | shield/nftables.go:56 setup 无条件 `delete table inet freesbc`，无实例隔离 |
| D7-8 | ✅ | shield/nftables.go:32 exec.LookPath("nft")，无路径配置字段 |
| D7-9 | ✅ | sig/server.go:419-421 dropUnidentified 每请求 Info 日志（对照 rate 分支 shield.go:89 为 Debug） |
| D7-10 | 🅿 | 指纹属实（scanner.go:11-23 含 sipsak），降级为计数 ban 是策略决策 |
| D7-11 | ✅ | config/types.go:132-135 rate 无上限（"1000000/s" 合法）；validate.go:163-165 允许亚秒 duration |
| D8-1 | ✅ | sig/resolve.go:46 lookupSRV 字段无 ctx 参数；:76-105 无去重、错误同 TTL 缓存（字段可注入，测试可写） |
| D8-2 | ✅ | sig/resolve.go:143-206 orderSRV 无 Target "."/Port 0 过滤（:198 TrimSuffix 把 "." 变空串） |
| D8-4 | ✅ | sig/resolve.go:99 与 :111 回退端口恒 5060（tls 应 5061，RFC 3263 §4.1） |
| D8-5 | ❌ | 非「报告有误」而是不可立项：CI/SBOM/签名是流程工作项，无针对本仓库代码的失败测试可写（建议单独立 ops 任务跟踪） |
| D8-6 | 🅿 | 部署/文档工作项（systemd 样例），无代码失败测试；随 T-17 一起交付文档 |
| D8-7 | ✅ | config/loader.go:11-17 不检查文件 mode（写回侧 config_write.go:113 已保 0600/继承） |
| D2-7 | ❌ | 报告自述「记录备查，无需代码变更」——无修复动作，不构成任务 |

## 3. 任务卡

> 通用验收（每卡均适用，卡内不再重复）：红测试转绿 + `go test ./... -race` 全绿 + `go vet ./...` 无新增告警。允许改动只列白名单；涉及新配置字段命名的（T-06/T-17/T-19/T-37），字段名是本任务的设计决策，评审可改名，红测试随之更新。

### T-01（F-01）SIP 入口前置过滤：非 peer 源字节在解析前丢弃
- 复核结论：已复核
- 当前位置：sig/server.go:166-169（NewUA 未传 readFilter 选项）；sipgo v1.4.3 transport_udp.go:177-184（pool.Add 先于 parseAndHandle，且在 readFilter 之后——钩子可用）
- 现有行为：任意源字节进入 sipgo 解析并按唯一源地址无界填充连接池，shield 在 handler 层才介入
- 期望行为：经 sipgo `WithTransportLayerReadFilter` 注入过滤函数：源 IP ∉ 任一 peer.allowed_ips 的 UDP/TCP/TLS 字节直接丢弃（返回空切片），不进入解析、事务、日志与连接池
- 红测试：sig/server_preparse_test.go :: TestPreParseFilterDropsNonPeerBytes :: 监听 127.0.0.2，peer allowed_ips 仅含 127.0.0.9，从 127.0.0.1 发一条缺 Via 的可解析请求 → 断言客户端在 2s 内收不到任何响应字节（当前 sipgo 事务层会回 400，测试 FAIL）
- 允许改动：sig/server.go、新文件 sig/readfilter.go、sig/server_test.go（若需调整装配辅助）
- 明确不做：不改 shield 包；不做 per-IP 限速（那是 shield 的事）；不解决 peer 源伪造（F-07 挂起中）
- 涉及符号：sipgo.WithUserAgentTransportLayerOptions（ua.go:76）、sip.WithTransportLayerReadFilter（sip/transport_layer.go:72）、config.Peer.AllowsIP（config/schema.go:66）、Server.store（sig/server.go:29）

### T-02（F-04）nft 封禁限定 SIP 端口 + UDP 单包判定仅内存封禁 + admin unban
- 复核结论：已复核
- 当前位置：shield/nftables.go:62-63（规则 `ip saddr @banned4 drop` 无 dport/协议限定）；shield.go:81-86（scanner 单包即写内核）；admin/server.go:63-75（无 unban 路由）
- 现有行为：任一非 peer IP 可被写入内核 input 链全协议 1h 黑洞，且无解除端点
- 期望行为：① 内核规则限定到配置的 SIP 监听端口与 udp/tcp 协议；② UDP 传输上的单包判定（scanner）只写内存 ban 表，不触发 nft（多包 auto-ban 或 TCP/TLS 来源才允许内核同步）；③ 新增 DELETE /api/bans/{ip}（requireAuth 后）同步清内存表与 nft 元素
- 红测试（主）：shield/nftables_test.go :: TestNFTBanRulesScopedToSIPPorts :: 用现有 newTestNFT（nftables_test.go:18）执行 setup() → 断言规则 argv 含端口限定（当前无 dport，FAIL）
- 红测试（次）：shield/shield_test.go :: TestUDPScannerSinglePacketMemoryOnly :: UDP 来源 Check 一次 scanner UA → 断言 nft run 记录为空（当前有 add element，FAIL）
- 允许改动：shield/nftables.go、shield/shield.go（Check 需感知传输类型——签名调整是本任务一部分）、shield/banlist.go、admin/server.go、admin/api.go
- 明确不做：不改 auto-ban 阈值语义；不做 nftables 默认值翻转（部署策略另行）
- 涉及符号：nftBackend.setup（nftables.go:53）、nftBackend.ban（:75）、Shield.Check（shield.go:72）、withShield（sig/server.go:377——传传输类型时的调用点）、mux 路由表（admin/server.go:63-75）

### T-03（F-05）banList 硬上限
- 复核结论：已复核
- 当前位置：shield/banlist.go:13-22（until map 无上限）、:60-69（prune 仅删过期）
- 现有行为：唯一源洪水在 auto_ban.duration（默认 1h）窗口内无界累积条目
- 期望行为：ban 表设硬上限（常量或 shield 配置，建议 65536）；超限时先懒惰清过期项，仍满则拒绝新增并计数暴露到 Stats（限速 Drop 分支不受影响）
- 红测试：shield/banlist_test.go :: TestBanListCap :: 假时钟注入（banList.now 可替换）ban 超上限数量的唯一 IP → 断言 len(until) ≤ 上限且超限计数 >0（当前无界增长，FAIL）
- 允许改动：shield/banlist.go、shield/shield.go（Stats 增超限计数）、admin/metrics.go（透出计数，可选）
- 明确不做：不做前缀聚合降级（后续优化）；不动 failCounter/ratelimit map（前者受 ban 前置短路约束，后者由 T-04 场景覆盖评估）
- 涉及符号：banList.until/ban/banned/prune（banlist.go:15,26,37,60）、Shield.Stats（shield.go:103）

### T-04（F-03）scanner 判定移到限速后 + nft exec 串行化/限幅
- 复核结论：已复核
- 当前位置：shield/shield.go:81-86（isScanner→ban 在 :87-92 限速之前）；shield/banlist.go:26-33（锁外同步 exec 无并发上限）；shield/nftables.go:39-41（exec.Command 无超时）
- 现有行为：UA 可控的即时 ban 信号绕过限速，每唯一源一次 fork+exec，无节流
- 期望行为：① Check 内 scanner 判定移到 limiter.allow 之后；② nftBackend 改为单 worker 串行消费有界队列（满则丢弃内核同步，内存 ban 兜底）；③ exec 换 CommandContext（建议 2s 超时）
- 红测试（主）：shield/shield_test.go :: TestScannerBanRespectsRateLimit :: 同一 IP 先发 rate+1 个普通包耗尽令牌 → 再发 scanner UA 包 → 断言未产生新 ban（当前仍 ban，FAIL）
- 红测试（次）：shield/nftables_test.go :: TestNFTExecBoundedAndSerialized :: 并发对 1000 个唯一 IP 触发 ban → 断言 run 记录数 ≤ 队列上限且任意时刻并发为 1（当前 1000 次同步 exec，FAIL）
- 允许改动：shield/shield.go、shield/banlist.go、shield/nftables.go、shield/nftables_test.go
- 明确不做：不实现同 IP 去重以外的聚合；不改 scanner 指纹库（D7-10 挂起）
- 涉及符号：Shield.Check（shield.go:72-94）、isScanner（scanner.go:27）、banList.ban（banlist.go:26）、nftBackend.run（nftables.go:18,39）

### T-05（F-02）SIP TCP/TLS：连接上限 + 空闲/读超时
- 复核结论：已复核
- 当前位置：sig/server.go:328-345（裸 net.Listen/tls.Listen 交给 sipgo）；sipgo v1.4.3 transport_tcp.go:62-72（accept 无上限）、:135-143（无读超时）、parser_stream.go Write/partial 无界
- 现有行为：连接数与每连接累积内存均无界，慢喂/静默连接永不回收
- 期望行为：包装 listener——全局并发连接上限（超限 accept 后立即 Close 并继续 Accept 循环，不得向 sipgo 返回 nil conn）；每连接 Read 前 Refresh 读截止（空闲超时，建议 120s；数值后续可进配置）
- 红测试：sig/server_tcplimit_test.go :: TestTCPIdleTimeoutClosesConn :: 连上 TCP 监听发半条请求行后静默 → 在空闲超时+余量内断言服务端关闭连接（当前连接永不关闭，测试超时 FAIL）
- 允许改动：sig/server.go（bindListener）、新文件 sig/listenerlimit.go、sig/server_test.go
- 明确不做：不改 sipgo 内部（流式累积上限提上游）；不做 per-IP 连接数限制（后续）
- 涉及符号：Server.bindListener（sig/server.go:324）、tl.ServeTCP/ServeTLS 调用点（:333,345）

### T-06（F-06，含 D6-8）per-peer 并发呼叫与 INVITE 速率上限
- 复核结论：已复核
- 当前位置：sig/b2bua.go:276-286（INVITE 即分配端口，无准入控制）；media/portpool.go:54-84；config/schema.go（无任何 max/limit 字段——grep 确认）
- 现有行为：单一 peer 源（可伪造）可用 ~70 INVITE/s 占满全部端口配额并触发真实出局话务
- 期望行为：新增配置 `peers.<name>.max_concurrent_calls`（0=不限）与全局 `max_concurrent_calls`；bridge 在 Identify 通过后检查配额，超限回 503 + Retry-After；呼叫结束（含失败路径）释放配额
- 红测试（主）：config/schema_test.go :: TestPeerMaxConcurrentCallsParses :: 含新字段的 YAML 通过 Parse（当前 Strict 解析拒未知键，FAIL）
- 红测试（次）：sig/b2bua_test.go :: TestPeerCallCapRejectsWith503 :: 复用现有呼叫测试装配（参照 b2bua_test.go:2033 的会话建立模式）把 peer 上限设为 1，第二路 INVITE → 断言 503（当前被接受，FAIL）
- 允许改动：config/schema.go、config/validate.go、sig/b2bua.go、sig/server.go（如需全局计数挂载）
- 明确不做：不做 A-leg ACK 前延迟拨号（架构变更另行）；不做媒体端口分配时机调整
- 涉及符号：bridge.onInvite（b2bua.go:80）、pool.Allocate（session.go:140）、config.Peer（schema.go:43）

### T-07（F-08）refresh re-INVITE 补 dialog 校验（Call-ID+双 tag）
- 复核结论：已复核
- 当前位置：sig/b2bua.go:127-151（仅查 To-tag 存在 + Call-ID 查 callSDPStore）；sig/callsdp.go:67-72；sig/timers.go:76-81
- 现有行为：任一已识别 peer 凭 Call-ID + 匹配 compare SDP 即可取回该腿 200 OK 应答（含 SDES master key）
- 期望行为：in-dialog 分支用 dialog ID（Call-ID + From-tag + To-tag，按 A/B 腿分别以 UAS/UAC 规则比对）校验请求确属该腿对话；不匹配回 481。腿建立时在 callSDP 中记录对话标识
- 红测试：sig/b2bua_test.go :: TestRefreshReInviteWrongTagsGet481 :: 按 TestBridgeAnswersSessionTimerRefresh（b2bua_test.go:2033）模式建立呼叫后，从另一 allowed peer 发同 Call-ID、同 compare body、但 From/To tag 错误的 refresh INVITE → 断言 481 且响应不含 SDP body（当前 200+answer，FAIL）
- 允许改动：sig/b2bua.go、sig/callsdp.go、sig/timers.go（如需）
- 明确不做：不实现媒体变更 re-INVITE（维持 501）；不改 isRefreshReInvite 比较算法本身
- 涉及符号：bridge.onInvite（b2bua.go:127-151）、callSDPStore.get（callsdp.go:67）、isRefreshReInvite（timers.go:76）、sip.DialogIDFromRequestUAS/UAC（sipgo sip/sip.go——存在性已在 sipgo 源码确认，实现时以该版本 API 为准）

### T-08（F-09）启用 SRTP/SRTCP 防重放
- 复核结论：已复核
- 当前位置：media/srtp.go:52（srtp.CreateContext 无 ContextOption）；media/srtp_relay_test.go:10-13（注释自认默认 no-replay）
- 现有行为：同一 SRTP 包重复解密每次都成功（重放放行），违反 RFC 3711 §3.3.2/§3.4.2
- 期望行为：NewSRTPContext 传入 pion 的 SRTP/SRTCP 防重放选项（窗口建议 64/128）；重放包 unprotect 失败 → relay 丢包（relay.go:50-60 现有 fail-closed 路径不变）
- 红测试：media/srtp_test.go :: TestSRTPReplayDropped :: 同一密文 unprotect 两次 → 断言第二次 ok==false（当前 true，FAIL）
- 允许改动：media/srtp.go、media/srtp_relay_test.go（pumpTransform :14 的重发泵依赖 no-replay，需同步改造为先单发再校验）、media/srtp_test.go
- 明确不做：不动 latch/SRTP 上下文管理（session.go SetSRTP）；不改 suite 支持
- 涉及符号：NewSRTPContext（srtp.go:46）、unprotectRTP/unprotectRTCP（srtp.go:68,82）、pumpTransform（srtp_relay_test.go:14）

### T-09（F-14，含 D3-3/D2-4/D6-7 的 admin 侧）admin 认证加固：失败限速 + 跳过无头 KDF
- 复核结论：已复核
- 当前位置：admin/server.go:102-105（r.BasicAuth() 无条件走 bcrypt，含无 Authorization 头请求）；:100-112（无失败计数/限速）
- 现有行为：未认证请求每条付出完整 bcrypt 成本且无失败上限（CPU-DoS + 无限爆破）
- 期望行为：① Authorization 头缺失时直接 401 不执行 bcrypt；② per-IP 失败限速（如 10 次/分钟，超限回 429）——限速状态有界并周期清理
- 红测试（主）：admin/server_test.go :: TestAdminAuthFailureRateLimit :: 同一 RemoteAddr 连发 11 个错误口令请求 → 断言第 11 个为 429（当前全部 401，FAIL；现有 TestAuthRequired :99 的装配可复用）
- 红测试（次）：admin/server_test.go :: TestRequireAuthSkipsKDFOnMissingHeader :: 无 Authorization 头请求的 P99 延时 <5ms（对照 bcrypt 参考值 60ms+，阈值宽裕防抖动；当前 FAIL）
- 允许改动：admin/server.go、admin/server_test.go
- 明确不做：不做账号锁定（单管理员模型）；不引入 session/CSRF token；TLS 由 T-17 承接
- 涉及符号：Server.requireAuth（server.go:100）、recoverMW（:115）、http.Server 配置（:80——IdleTimeout 由 T-24 承接，本任务不动）

### T-10（F-17）全链路 IP 规范化（Unmap）
- 复核结论：已复核
- 当前位置：sig/server.go:391-401（sourceAddr 无 Unmap；全仓 Unmap 仅 media/session.go:82）
- 现有行为：4-in-6 源地址在 identify/ban/ratelimit 三处与 v4 前缀互不匹配（fail-closed 断呼、ban 键双份、nft 误写 banned6）
- 期望行为：sourceAddr 出口统一 .Unmap()；shield.Check 入口防御性 Unmap；nft ban 选集合时对 4-in-6 判 Is4In6（双保险）
- 红测试：sig/identify_test.go :: TestIdentifyPeerUnmaps4in6 :: cfg.allowed_ips 含 203.0.113.0/24，IdentifyPeer(cfg, ::ffff:203.0.113.7) → 断言 ok==true（当前 false，FAIL；IdentifyPeer 已导出，identify.go:17）
- 允许改动：sig/server.go、shield/shield.go、shield/nftables.go、sig/identify_test.go
- 明确不做：不改 config 前缀解析（validate.go:257-266）；不做监听 host 校验（另行）
- 涉及符号：sourceAddr（server.go:391）、Shield.Check（shield.go:72）、IdentifyPeer（identify.go:17）、netip.Addr.Unmap（标准库）

### T-11（F-16）allowed_ips 校验：非空 + 宽度上限 + 规范前缀
- 复核结论：已复核
- 当前位置：config/validate.go:98-106（无非空/宽度/规范性检查）；:257-266（不 Masked）
- 现有行为：`allowed_ips: [0.0.0.0/0]` 静默通过（叠加源 IP 信任=任意源盗打）；空列表静默 fail-closed
- 期望行为：validate 拒绝 ① 空 allowed_ips；② 过宽前缀（建议阈值：IPv4 >/16、IPv6 >/48 报错，可配跳过）；③ 非规范前缀（存 pfx.Masked() 或报错，实现定其一并写明）
- 红测试：config/validate_test.go :: TestValidateRejectsWildcardPrefix :: allowed_ips=["0.0.0.0/0"] 的 YAML → 断言 Parse 返回错误且信息含 "allowed_ips"（当前解析成功，FAIL）
- 允许改动：config/validate.go、config/validate_test.go、config/schema.go（如需阈值配置）
- 明确不做：不做 peer 级 allowlist 叠加语义；不改 IdentifyPeer 匹配逻辑
- 涉及符号：Config.validate（validate.go:21）、parsePrefixOrAddr（:257）、Peer.AllowedIPs（schema.go:48）

### T-12（F-10）杂散 response 静默处理（UnhandledResponseHandler）
- 复核结论：已复核
- 当前位置：sig/server.go:179（sipgo.NewClient 未设 UnhandledResponseHandler）；sipgo transaction_layer.go:18-20（默认每包 Info 日志）
- 现有行为：任意源发杂散 SIP response → 每包一个 goroutine + 一条 Info 日志（未认证日志洪泛）
- 期望行为：NewClient 设置 UnhandledResponseHandler：静默计数（暴露到 metrics 可选），不逐包记日志。注：解析失败全字节日志与事务层 400 的收口由 T-01 的前置过滤承担，本任务只做 response 路径
- 红测试：sig/server_test.go :: TestStrayResponseNotLoggedPerPacket :: 捕获 slog 输出发送一条杂散 response → 断言无 Info 级日志产生（当前 defaultUnhandledRespHandler 每包 Info，FAIL）
- 允许改动：sig/server.go、sig/server_test.go
- 明确不做：不封装 sipgo 事务层日志（上游）；不动 400 路径（T-01 覆盖）
- 涉及符号：sipgo.NewClient（sig/server.go:179）、sipgo 客户端选项（以 v1.4.3 API 为准，存在性已核）

### T-13（F-12）身份字段清洗：拒绝裸 LF 与引号破坏
- 复核结论：已复核
- 当前位置：sig/b2bua.go:1089-1103（buildFrom 原样透传 DisplayName/User）；:752-753（outNumber → Request-URI user）；routing.go:44-50
- 现有行为：A-leg From 的 display name/user 与被叫号码可携带裸 \n 与未配对 `"` 直达 B-leg 序列化（对宽松栈=头注入）
- 期望行为：buildFrom 与 Request-URI user 写入前剔除/拒绝 CR/LF（建议直接剔字符）；display name 另剔 `"` `<` `>`；被叫号码做字符白名单校验（不匹配即 400）
- 红测试：sig/b2bua_test.go :: TestBuildFromStripsLFAndQuotes :: 构造 From display name 含 "\nX-Evil: 1" 与内嵌 `"` 的请求走 buildFrom → 断言产出 From 头序列化后不含 \n 且引号配对（当前含原样字节，FAIL）
- 允许改动：sig/b2bua.go、sig/routing.go、sig/b2bua_test.go
- 明确不做：不做完整 RFC 3261 quoted-string 转义器（剔除已足够）；不动 sipgo 序列化
- 涉及符号：bridge.buildFrom（b2bua.go:1089）、bTarget.User 赋值点（:753）、transformNumber（routing.go:44）

### T-14（F-11，含 D5-5）SDP relay 段属性白名单
- 复核结论：已复核
- 当前位置：sig/sdp.go:176-190（rewriteSDPCrypto relay 段"keep everything except crypto/rtcp"）；:59-61（o= 只改地址）
- 现有行为：a=candidate/a=fingerprint/a=ice-*/o= 会话标识跨腿透传（内网拓扑泄露）
- 期望行为：relay 段改属性白名单（rtpmap/fmtp/ptime/maxptime/sendrecv/sendonly/recvonly/inactive/方向类），白名单外丢弃；o= 的 username 与 sess-id 重写为 SBC 生成值（保留版本号递增语义）；declined 段行为不变（:198-200）
- 红测试：sig/sdp_test.go :: TestRewriteDropsCandidateAndFingerprint :: 含 a=candidate/a=fingerprint/a=ice-ufrag 的 offer 经 rewriteSDPCrypto → 断言输出不含这些属性行（当前透传，FAIL）
- 允许改动：sig/sdp.go、sig/sdp_test.go
- 明确不做：不做地址重写式 ICE 支持；不动 crypto 行处理（已正确）
- 涉及符号：rewriteSDPCrypto（sdp.go:149）、rewriteSDP（:45）、firstAudio（:222）

### T-15（F-15）admin 凭据/监听热生效
- 复核结论：已复核
- 当前位置：main.go:104,127（启动期固化）；admin/server.go:59（cfg 字段不再更新）、:103-104
- 现有行为：热重载更换 password_hash 后旧口令重启前持续有效；删除 admin 段不关闭 admin API
- 期望行为：requireAuth 每请求从 store.Current() 读 Admin 配置（bcrypt 成本不变，无额外代价）；Run 的监听地址变化仍需重启（此情形打显著 WARN 并保持旧监听）
- 红测试：admin/server_test.go :: TestAdminAuthHotReloadRevokesOldPassword :: admin.New 后 store.Replace 换新 hash → 旧口令请求断言 401（当前 200，FAIL；store.Replace 存在，config/store.go:29）
- 允许改动：admin/server.go、admin/server_test.go、main.go（如需传 store 引用——已传）
- 明确不做：不做热重启监听器；不做多管理员
- 涉及符号：Server.cfg（server.go:47）、config.Store.Current/Replace（store.go:25,29）、requireAuth（server.go:100）

### T-16（F-18）敏感响应 Cache-Control: no-store
- 复核结论：已复核
- 当前位置：admin/config_write.go:64-79（/api/config/raw 仅 Content-Type+ETag）；admin/api.go:11-14（writeJSON）
- 现有行为：含明文凭据的配置原文可落浏览器磁盘缓存
- 期望行为：recoverMW 统一注入 `Cache-Control: no-store`（/healthz 可豁免）；保持现有 ETag 语义
- 红测试：admin/server_test.go :: TestSensitiveResponsesNoStore :: 认证 GET /api/config/raw 与 /api/config → 断言响应头含 Cache-Control: no-store（当前缺失，FAIL）
- 允许改动：admin/server.go（recoverMW）、admin/server_test.go
- 明确不做：不加 CSP 等其他头（T-25 承接）；不动 ETag/If-Match 逻辑
- 涉及符号：recoverMW（server.go:115）、handleConfigRaw（config_write.go:64）、writeJSON（api.go:11）

### T-17（F-13，含 D1-11）TLS 凭据配置面
- 复核结论：已复核
- 当前位置：sig/tlscert.go:21-54（恒自签，注释自认无证书配置）；sig/server.go:334-345（固定调 selfSignedTLSConfig）；config/schema.go（无任何 TLS 字段）
- 现有行为：入向 TLS 无法配真证书/mTLS；出向无法配信任锚（自签运营商不可达）；transport=tls 时不告警
- 期望行为：新增配置：入向 `listen.tls_cert`/`listen.tls_key`/`listen.tls_client_ca`（mTLS 可选；未配置时维持自签但对 tls 监听打 WARN）；出向 `peers.<name>.tls_ca`/`tls_client_cert`/`tls_client_key`；显式 MinVersion=TLS1.2
- 红测试（主）：config/schema_test.go :: TestTLSConfigFieldsParse :: 含上述字段的 YAML 通过 Parse（当前 Strict 拒绝，FAIL）
- 红测试（次）：sig/server_test.go :: TestTLSListenerUsesConfiguredCert :: 配置证书起 TLS 监听，客户端（TLSClientConfig 不跳过校验、RootCAs 含该证书）握手成功且对端证书非 "FreeSBC self-signed" CN（当前自签握手校验失败，FAIL）
- 允许改动：config/schema.go、config/validate.go、sig/tlscert.go、sig/server.go、main.go（如需）
- 明确不做：不做 DTLS/SRTP；不做证书热轮换（重启生效即可，写明）；pinning（F-21 挂起项）本任务不做
- 涉及符号：selfSignedTLSConfig（tlscert.go:21）、bindListener tls 分支（server.go:334）、SIPListen（config/types.go:76）、Peer（schema.go:43）

### T-18（F-19）peer 宽松限速（取代全免）
- 复核结论：已复核
- 当前位置：shield/shield.go:74-76（isConfiguredPeer 直接 Allow）
- 现有行为：peer 源完全豁免限速 → 伪造 peer IP 的洪泛无速率上界（与 T-06 的 F-06/D6-6 叠加）
- 期望行为：peer 源走宽松限速（独立的高阈值，如可配 `shield.peer_rate_limit`，缺省 200/s per_ip）；超限 Drop
- 红测试：shield/shield_test.go :: TestShieldCheckAppliesPeerRateLimit :: peer IP 连续 Check 超过阈值 → 断言返回 Drop（当前恒 Allow，FAIL）
- 允许改动：shield/shield.go、shield/ratelimit.go、config（如新增字段）、shield/shield_test.go
- 明确不做：不给 peer 应用 scanner/ban 逻辑（保持豁免语义）；不实现 per-peer 独立阈值矩阵
- 涉及符号：Shield.Check（shield.go:72）、rateLimiter.allow（ratelimit.go:33）、isConfiguredPeer（shield.go:167）

### T-19（F-20）digest realm 钉扎
- 复核结论：已复核
- 当前位置：sig/register.go:~101（DoDigestAuth 直接消费远端 challenge）；config/schema.go:75-78（PeerAuth 仅 Username/Password）
- 现有行为：realm/nonce/algorithm 全由远端控制；challenge 可指向任意 realm
- 期望行为：PeerAuth 新增 `realm` 字段（可选）；设置后，REGISTER/INVITE 的 401/407 challenge realm 不匹配时不做摘要应答（按认证失败处理）
- 红测试（主）：config/schema_test.go :: TestPeerAuthRealmParses :: auth.realm 字段通过 Parse（当前拒绝，FAIL）
- 红测试（次）：sig/register_test.go :: TestRegisterRejectsUnexpectedRealm :: 假 registrar（现有测试桩模式，register_test.go 已有 fake server）返回 realm="evil" → 断言未发出带 Authorization 的重试（当前无条件应答，FAIL）
- 允许改动：config/schema.go、sig/register.go、sig/b2bua.go（WaitAnswer 凭据路径如需）、sig/register_test.go
- 明确不做：不做 algorithm 白名单强制（后续）；不改 qop 处理（sipgo 内部）
- 涉及符号：PeerAuth（schema.go:75）、registerOnce 的 DoDigestAuth 调用（register.go:~96-105）、sipgo.DigestAuth（v1.4.3）

### T-20（D1-8）全部 SIP handler panic 恢复 + 必备头校验
- 复核结论：已复核
- 当前位置：sig/server.go:488-582（onOptions/onAck/onBye/onNoRoute 无 recover）；b2bua.go:127（缺 To 头 nil-deref，现靠 :81 recover 静默吞掉且无 400）
- 现有行为：除 onInvite 外任一 handler（或其调用的 sipgo dialog 代码）panic = 进程退出；缺 To/From 的 INVITE 被静默丢弃无 400
- 期望行为：① withShield 统一 defer recover（记 Error + 尽力 500）；② onInvite 入口显式校验 From/To/Call-ID 存在，缺失回 400
- 红测试：sig/b2bua_test.go :: TestInviteMissingToGets400 :: peer 源发缺 To 头的 INVITE → 断言收到 400（当前无任何响应，FAIL）
- 允许改动：sig/server.go、sig/b2bua.go、sig/b2bua_test.go
- 明确不做：不替 sipgo 事务层加 recover（上游）；不逐 handler 手写校验（入口统一）
- 涉及符号：withShield（server.go:377）、recoverCall（b2bua.go:1341）、onInvite（b2bua.go:80）

### T-21（D7-9）dropUnidentified 日志降级
- 复核结论：已复核
- 当前位置：sig/server.go:419-421（每请求一条 Info）
- 现有行为：未识别源洪泛 → 每包一行 Info（≈260GB/天 @2 万行/秒量级）
- 期望行为：降为 Debug + 周期聚合（如每分钟一条计数摘要，挂现有 pruneLoop 或独立 ticker）；shield.Scan 计数保持
- 红测试：sig/server_test.go :: TestDropUnidentifiedNotInfoPerPacket :: 捕获 slog，发一条未识别请求 → 断言无 Info 级"dropping request from unidentified source"（当前 Info，FAIL）
- 允许改动：sig/server.go、sig/server_test.go
- 明确不做：不删日志（保留 Debug 与聚合）；不动 shield 侧日志（T-04 顺带覆盖 Warn 采样）
- 涉及符号：dropUnidentified（server.go:418）、RecordUnidentified 调用点（:424-428）

### T-22（D5-4）watchdog 仅在 SRTP 认证通过后刷新 lastRx
- 复核结论：已复核
- 当前位置：media/relay.go:45（lastRx.Store 先于 :50-60 unprotect）
- 现有行为：知悉 latched 地址者可用垃圾包无限续期 rtp_timeout
- 期望行为：lastRx 仅在（若配置 SRTP）unprotect 成功或明文路径 accept 通过后刷新；垃圾包不再重置看门狗
- 红测试：media/relay_test.go :: TestWatchdogIgnolesUnauthKeepalive :: 小超时（如 80ms）会话 + SideA 装配 SRTP，从已 latch 地址每 20ms 发垃圾包 → 断言 Done() 在 3×超时 内关闭（当前被无限续期，FAIL；时间余量已放宽）
- 允许改动：media/relay.go、media/relay_test.go
- 明确不做：不改 watchdog 间隔算法；不做每包日志
- 涉及符号：Session.lastRx（relay.go:45 读写）、forward（relay.go:27）、watchdog（relay.go:81）

### T-23（D6-9，含 D1-9/D2-6）重复 Call-ID 呼叫拒绝（482）
- 复核结论：已复核
- 当前位置：callstate/registry.go:28-32（Add 覆盖）；sig/b2bua.go:303-327（killers/registry/sdps 三表同键覆盖-误删）
- 现有行为：并发同 Call-ID 第二呼叫覆盖三表条目，先结束者删掉后者的 killer → 后者无法被管理员踢除
- 期望行为：onInvite 在 registerKiller 前检测同 Call-ID 呼叫已在册 → 回 482 Loop Detected 拒绝第二通（选择拒绝而非复合键：改动最小且语义正确）
- 红测试：sig/b2bua_test.go :: TestDuplicateCallIDSecondInviteGets482 :: 建立呼叫 A（已知 Call-ID），同源再发同 Call-ID INVITE → 断言 482（当前进入正常呼叫流程，FAIL）
- 允许改动：sig/b2bua.go、callstate/registry.go（如需 Exists 查询）、sig/b2bua_test.go
- 明确不做：不改三表键结构；不做 Call-ID 格式校验（D3-5 挂起）
- 涉及符号：bridge.onInvite 注册段（b2bua.go:303-327）、Registry.Add/Remove（registry.go:28,35）、registerKiller（server.go:98）

### T-24（D3-4）admin http.Server 超时补全
- 复核结论：已复核
- 当前位置：admin/server.go:80（仅 ReadHeaderTimeout=5s）
- 现有行为：空闲 keep-alive 连接永不回收、无连接上限（/healthz 免认证军团可耗 fd/goroutine）
- 期望行为：补 IdleTimeout（建议 30s）、ReadTimeout（建议 30s，注意 PUT 1MiB 的时长余量）、WriteTimeout（建议 30s）；/healthz 保持免认证
- 红测试：admin/server_test.go :: TestAdminIdleTimeoutClosesConn :: 原生 TCP 连上 admin 发一个完整请求后静默 → 断言 IdleTimeout+余量内被服务端关闭（当前永不关闭，FAIL）
- 允许改动：admin/server.go、admin/server_test.go
- 明确不做：不做连接数上限（后续可加，非本发现最低修复）；不动 /healthz 语义
- 涉及符号：Server.Run 的 http.Server（server.go:80）

### T-25（D3-2）安全响应头基线
- 复核结论：已复核
- 当前位置：admin/server.go:115-132（recoverMW 是唯一统一注入点，现无任何安全头）
- 现有行为：HTML/JSON/YAML 响应无 nosniff/CSP/XFO/Referrer-Policy
- 期望行为：recoverMW 注入 `X-Content-Type-Options: nosniff`、`X-Frame-Options: DENY`、`Referrer-Policy: no-referrer`；`/`（webui.go:14）另加最小 CSP（default-src 'self'，内联脚本按 index.html 现状配 nonce 或 script-src 'unsafe-inline' 的过渡方案——实现定并写明取舍）
- 红测试：admin/server_test.go :: TestSecurityHeadersPresent :: 认证 GET / 与 /api/config/raw → 断言含 nosniff 与 XFO（当前缺失，FAIL）
- 允许改动：admin/server.go、admin/webui_test.go（如需）、admin/server_test.go
- 明确不做：不加 HSTS（无 TLS，待 T-17 后）；不重构 WebUI 去内联脚本
- 涉及符号：recoverMW（server.go:115）、handleUI（webui.go:14）

### T-26（D4-6）admin 监听与 bcrypt cost 校验
- 复核结论：已复核
- 当前位置：config/validate.go:167-170（非 loopback 静默通过）、:174-176（bcrypt.Cost 无下限）
- 现有行为：0.0.0.0:8080 明文 Basic 静默放行；cost 4 哈希合法（爆破便宜 ~50 倍）
- 期望行为：① 非 loopback admin.listen 默认拒绝，新增 `admin.allow_remote: true` 显式放行（放行时校验错误信息提示 TLS 建议）；② bcrypt cost <10 拒绝
- 红测试（主）：config/validate_test.go :: TestValidateRejectsNonLoopbackAdmin :: admin.listen=0.0.0.0:8080 且无 allow_remote → 断言 Parse 报错（当前通过，FAIL）
- 红测试（次）：config/validate_test.go :: TestValidateRejectsLowBcryptCost :: cost 4 哈希 → 断言报错（当前通过，FAIL）
- 允许改动：config/validate.go、config/schema.go、config/validate_test.go
- 明确不做：不做 admin TLS（T-17）；不做运行时监听告警（校验期拦截已足够）
- 涉及符号：AdminConfig（schema.go:115）、validate admin 段（validate.go:167-176）、bcrypt.Cost（x/crypto）

### T-27（D7-11）shield 参数上限校验
- 复核结论：已复核
- 当前位置：config/types.go:132-135（rate 数值无上限）；config/validate.go:163-165（duration 允许亚秒→nft timeout 截断 "0s"）
- 现有行为：`rate_limit: "1000000/s per_ip"` 合法（failCounter 内存放大）；500ms ban 时长把内核 timeout 变 0s
- 期望行为：ParseRateLimit 之上校验 rate ≤ 上限（建议 1000）；auto_ban.duration ≥1s（或 nft timeout 向上取整到整秒）
- 红测试（主）：config/types_test.go :: TestParseRateLimitCapOrValidateRejectsHuge :: "1000000/s per_ip" 的完整 config → 断言 Parse 报错（当前通过，FAIL）
- 红测试（次）：config/validate_test.go :: TestAutoBanDurationAtLeastOneSecond :: duration=500ms → 断言报错（当前通过，FAIL）
- 允许改动：config/types.go、config/validate.go、对应 _test.go
- 明确不做：不动 ratelimit.go 算法；不做 failCounter 结构改造（T-03 已封顶）
- 涉及符号：ParseRateLimit（types.go:116）、AutoBan 校验段（validate.go:160-165）

### T-28（D8-1）DNS 解析超时 + singleflight + 失败短缓存
- 复核结论：已复核
- 当前位置：sig/resolve.go:46（lookupSRV 字段无 ctx）、:76-105（锁外无去重并发直查；err/空结果同 TTL 缓存 :103）
- 现有行为：慢 DNS 逐呼叫阻塞 goroutine；缓存过期瞬间 N 并发=N 次查询；瞬时故障负缓存整 300s
- 期望行为：lookupSRV 走带 context 的查询（WithTimeout，建议 2-3s）；同 host 并发去重（x/sync/singleflight 已是间接依赖）；失败/空结果短 TTL（建议 5-10s）单独缓存
- 红测试（主）：sig/resolve_test.go :: TestResolveHonorsTimeout :: 注入 stub lookupSRV（字段可注入，resolve.go:46）sleep 300ms → 断言 Resolve 在 200ms 内返回回退端点（当前阻塞 300ms，FAIL）
- 红测试（次）：sig/resolve_test.go :: TestResolveSingleflight :: 并发 10 个 Resolve 同 host + 计数 stub → 断言 stub 调用数为 1（当前为 10，FAIL）
- 允许改动：sig/resolve.go、sig/resolve_test.go、go.mod（singleflight 转直接依赖——需评审确认，不改 go.sum 语义）
- 明确不做：不做 DNSSEC；不做解析器自定义 Dial；不动 health 冷却
- 涉及符号：Resolver.lookupSRV/now（resolve.go:46-47）、resolveSRV（:76）、srv_cache_ttl（schema.go:28）

### T-29（D8-2）SRV 记录语义过滤
- 复核结论：已复核
- 当前位置：sig/resolve.go:143-206（orderSRV 无过滤；:198 Target "." → 空串、:199 Port 直收）
- 现有行为：Target "."（RFC 2782 = 服务不可用）与 port 0 记录生成坏端点进入 failover 链
- 期望行为：orderSRV（或其调用处）跳过 Target=="." 与 Port==0 的记录；过滤后为空时按无 SRV 回退处理
- 红测试：sig/resolve_test.go :: TestResolveSkipsNullTargetAndPortZero :: stub 返回 [".":5060, "a.example.":0, "ok.example.":5061] → 断言端点列表仅含 ok.example.:5061（当前含空 Host 与 0 端点项，FAIL）
- 允许改动：sig/resolve.go、sig/resolve_test.go
- 明确不做：不做 port 范围校验（1-65535 由拨号层报错）；不做权重修正
- 涉及符号：orderSRV（resolve.go:143）、Endpoint（:19）、resolveSRV（:76）

### T-30（D8-4）tls 传输的回退端口 5061
- 复核结论：已复核
- 当前位置：sig/resolve.go:99（SRV 缺失/失败回退 {Port:5060} 不分传输）、:111（classifyAddress 缺省 5060）
- 现有行为：transport=tls 的 peer 无 SRV 时拨 host:5060 over TLS（RFC 3263 §4.1 sips 回退应为 5061）→ 拨错端口呼叫失败
- 期望行为：回退与缺省端口按 transport 映射：tls→5061，udp/tcp→5060
- 红测试：sig/resolve_test.go :: TestTLSPeerFallsBackTo5061 :: peer{address:"host.example", transport:"tls"} + stub 无 SRV → 断言端点 Port==5061（当前 5060，FAIL）
- 允许改动：sig/resolve.go、sig/resolve_test.go、sig/register.go:390（splitHostPortDefault 缺省 5060 同步修）
- 明确不做：不做可配置端口映射；不动 SRV 优先序
- 涉及符号：resolveSRV 回退（resolve.go:98-99）、classifyAddress（:110）、splitHostPortDefault（register.go——存在性已核）

### T-31（D4-7）Load 文件大小上限
- 复核结论：已复核
- 当前位置：config/loader.go:11-17（os.ReadFile 整读无上限；对照 config_write.go:59 的 1MiB）
- 现有行为：配置路径被换成超大文件时整读进内存（本地威胁面）
- 期望行为：Load 用 io.LimitReader 限制（建议与 PUT 一致 1MiB+1，超出报错）
- 红测试：config/loader_test.go :: TestLoadRejectsOversizedFile :: 写 >1MiB 临时文件 → 断言 Load 返回错误（当前正常读取，FAIL）
- 允许改动：config/loader.go、config/loader_test.go
- 明确不做：不做权限检查（T-32）；不动 Parse
- 涉及符号：Load（loader.go:11）、maxConfigBytes（admin/config_write.go:59——常量如复用需移至共享处，实现定）

### T-32（D8-7）配置文件权限检查
- 复核结论：已复核
- 当前位置：config/loader.go:11-17（不查 mode；写回侧 config_write.go:113-117 已保 0644→0644 继承，另一任务 T-33 处理）
- 现有行为：`cp` 出的 0644 sbc.yaml 含明文密码即全局可读，加载无任何提示
- 期望行为：Load 时文件 mode 的 group/other 读位被置位且配置含凭据字段 → 返回明确错误（提示 chmod 600）——fail-closed（比告警可测试且安全；如评审倾向告警，需先给 Load 加日志通道，另行决策）
- 红测试：config/loader_test.go :: TestLoadRejectsWorldReadableConfigWithSecrets :: 0644 + 含 auth.password 的文件 → 断言 Load 报错；同内容 0600 → 断言成功（当前 0644 也成功，FAIL）
- 允许改动：config/loader.go、config/loader_test.go
- 明确不做：不自动 chmod；不检查属主
- 涉及符号：Load（loader.go:11）、PeerAuth.Password（schema.go:77）

### T-33（D4-3）写回文件权限收紧
- 复核结论：已复核
- 当前位置：admin/config_write.go:113-116（Stat 跟随符号链接取 target mode 并继承）
- 现有行为：原文件 0644 → 写回后仍 0644（含明文凭据时可被本地用户读）
- 期望行为：写回目标恒 0600（不再继承宽松位；若原 mode 更严格则保留更严格者）
- 红测试：admin/config_write_test.go :: TestConfigWriteResultMode0600 :: 预置 0644 配置文件走 PUT → 断言写回后 Perm()==0600（当前 0644，FAIL；现有测试 :274-298 固化了继承行为，需同步更新——属预期变更）
- 允许改动：admin/config_write.go、admin/config_write_test.go
- 明确不做：不递归改目录权限；不做 Lstat（T-34 承接 symlink）
- 涉及符号：handleConfigWrite（config_write.go:86）、writeFileAtomic（:26）、os.Chmod 调用（:48）

### T-34（D4-5）symlink 拒写 + 目录 fsync
- 复核结论：已复核
- 当前位置：admin/config_write.go:26-57（writeFileAtomic：无 Lstat 检查、rename 后无目录 fsync）
- 现有行为：cfgPath 为符号链接时 PUT 把链接替换为普通文件（部署布局被悄悄改变）；崩溃后 rename 可能丢失（耐久性）
- 期望行为：写前 Lstat 检测 symlink → 拒绝（409，提示不支持符号链接部署）；rename 成功后 fsync 目录
- 红测试：admin/config_write_test.go :: TestConfigWriteRefusesSymlinkPath :: sbc.yaml→real.yaml 符号链接走 PUT → 断言 409 且链接与真身均未被替换（当前链接被替换为普通文件，FAIL）
- 允许改动：admin/config_write.go、admin/config_write_test.go
- 明确不做：目录 fsync 不写独立断言（无可靠失败注入），作为实现要求随代码评审验收
- 涉及符号：writeFileAtomic（config_write.go:26）、os.Rename（:52）、os.CreateTemp（:28）

### T-35（D7-6）nftables 模式热重载生效
- 复核结论：已复核
- 当前位置：shield/shield.go:26-47（nft backend 构造期固定，注释自认）；config.Store.Replace 存在但 shield 不订阅
- 现有行为：on/auto→off 热重载后 ban 仍写内核；off→on 静默不生效
- 期望行为：shield 订阅 Store 变更（store.Subscribe，store.go:45），nftables 模式变化时重建/拆除 backend（拆=close+清元素；建=setup）；失败回退内存并 Error
- 红测试：shield/shield_test.go :: TestNFTablesModeHotReloadStopsKernelWrites :: 内存构建 Shield（同包可直构）挂录制 backend + store.Replace(nftables:"off") → 触发 ban → 断言无 nft 调用（当前仍调用，FAIL）
- 允许改动：shield/shield.go、shield/nftables.go、shield/shield_test.go
- 明确不做：不做逐元素迁移（模式切换即全量重建）；不处理 Listen 变化
- 涉及符号：Shield.New/Close（shield.go:51,129）、Store.Subscribe（store.go:45）、newNFTBackend（nftables.go:28）

### T-36（D7-7）nft 表实例隔离
- 复核结论：已复核
- 当前位置：shield/nftables.go:56（setup 无条件 `delete table inet freesbc`）、:57-64（固定表名）
- 现有行为：同 netns 双实例互删对方的表；operator 同名表被删；setup 部分失败残留
- 期望行为：表名带实例成分（如 `freesbc-<实例标识>`）或 setup 前探测创建者标记；close 只删自己的表；setup 失败回滚已建对象
- 红测试：shield/nftables_test.go :: TestNFTSetupDoesNotBlindDeleteSharedTable :: newTestNFT 执行 setup → 断言 argv 中 delete 仅指向本实例表名（当前无条件删 `inet freesbc`，FAIL）
- 允许改动：shield/nftables.go、shield/nftables_test.go
- 明确不做：不做跨 netns 协调；不迁移旧表名存量（首次运行自清，写明）
- 涉及符号：nftBackend.setup/close（nftables.go:53,88）、newTestNFT（nftables_test.go:18）

### T-37（D7-8）nft 二进制路径可配
- 复核结论：已复核
- 当前位置：shield/nftables.go:32（exec.LookPath("nft")，无配置）
- 现有行为：二进制位置取决于进程 PATH（root 进程 + 可写 PATH 目录 = 本地劫持面）
- 期望行为：新增 `shield.nftables_path`（缺省 /usr/sbin/nft 或空=维持 LookPath 行为并 WARN）；启动时校验属主/权限
- 红测试：config/schema_test.go :: TestShieldNftablesPathParses :: 含 shield.nftables_path 的 YAML 通过 Parse（当前 Strict 拒绝，FAIL）
- 允许改动：config/schema.go、config/validate.go、shield/nftables.go、shield/nftables_test.go
- 明确不做：不做签名校验；不做 setuid 处理
- 涉及符号：newNFTBackend（nftables.go:28）、exec.LookPath（:32）、ShieldConfig（schema.go:103）

## 4. 驳回清单

| 编号 | 为什么不成立/不立项 | 查过的位置 |
|------|---------------------|------------|
| D8-5（供应链 CI/SBOM/签名） | 非「报告有误」而是不可立项：工作项是新增 CI 配置与发布流程，不存在针对现有代码、当前会 FAIL 的测试断言。建议作为独立 ops 任务跟踪（报告 §9.18 已含） | find 全仓无 Makefile/CI/Dockerfile（复核确认）；README.md:30 裸 go build |
| D2-7（SSRF-by-config） | 报告自身定性「记录备查、无需代码变更」（报告领域二节原文）：出向目标只能被本地配置/已认证 PUT/DNS 改写，无未授权可达路径，无修复动作可定义 | sig/register.go:389-397、sig/resolve.go:64-105、sig/b2bua.go:752-758 |

## 5. 挂起清单

| 编号 | 缺什么才能判定 |
|------|----------------|
| F-07（源 IP 即身份） | 产品决策：是否实现入向 digest 质询/mTLS（新能力，需先定义 schema 与质询流程才能写红测试）。部署侧缓解（仅 tcp/tls + uRPF）是运维文档项 |
| F-21（DNS 信任链） | 可实现观测点缺失：A/AAAA 解析发生在 sipgo 发送时（resolve.go:71,99 只产出主机名端点），仓库层无从挂"解析到私网告警"；pinning 配置与 T-17 重叠——T-17 落地后重估剩余部分 |
| D4-2（goccy 别名炸弹） | Go 环境运行 PoC 确认崩溃复现（机制已对 goccy v1.19.2 上游源码核验）；确认后即可立项（红测试：自引用别名 YAML 的 Parse 必须返回 error 而非崩溃） |
| D4-4（PUT TOCTOU） | 串行化设计决策（Server 级互斥 vs If-Match 强制）；竞态时序无法写出确定性红测试，设计定案后以「并发 PUT 恰一者 409」立项 |
| D4-8（watcher 静默死亡） | 需重构 reload.go 暴露 fsnotify 注入点（Events 非正常关闭无法从外部触发），或 Go 环境复现触发路径 |
| D3-5（无上限 Call-ID） | 影响上限未证实（报告自评前置条件高）；T-01 落地后非 peer 源已被前置丢弃，重新评估残余攻击面再定 |
| D5-3（strict 仅 IP arming） | 设计取舍（SSRC 预学习 vs NAT 兼容性）需产品决策；文档化部分属文档工作项 |
| D5-7（RTCP CNAME 透传） | 剥/重写 CNAME 的互操作影响需运营商侧验证；属可选加固 |
| D7-10（sipsak 误杀） | 策略决策：双用途工具是否降级为计数 ban、是否提供 per-peer 关闭指纹 |
| D8-6（root 运行/降权） | 部署文档工作项（systemd AmbientCapabilities 样例），无代码失败测试；建议与 T-17 的文档一起交付 |

## 6. 执行顺序与依赖

**第一梯队（公网部署阻断项，先做）**：T-01 → T-03 → T-04 → T-02 → T-05 → T-06
- T-01 最先：前置过滤同时消除 F-01/F-10 的主触发面，并显著缩小 T-02/T-04 的攻击入口；
- T-04 → T-02 有序：两者都改 Shield.Check（T-02 需给 Check 增加传输类型参数），先落 T-04 的重排与队列，再做 T-02 的分传输 ban 策略，避免同函数两次冲突性重构；
- T-02/T-35/T-36/T-37 同文件（shield/nftables.go）：建议按 T-02 → T-36 → T-37 → T-35 顺序分批合入；
- T-06 与 T-18（第二梯队）共同覆盖 F-06/F-19 的洪泛面，T-06 先（配额比限速对端口池更直接）。

**第二梯队（认证与跨租户隔离）**：T-07 → T-08 → T-09 → T-15 → T-26
- T-07 优先于一切媒体面：密钥泄露入口；T-08 需同步改造 pumpTransform 测试泵（srtp_relay_test.go:14）。

**第三梯队（注入/泄露/配置面）**：T-10 → T-11 → T-13 → T-14 → T-12 → T-16 → T-17 → T-19
- T-12 依赖 T-01 先行（其红测试观察点在 T-01 后才稳定）；T-17 建议早于 T-19（schema 惯例先立）。

**第四梯队（Low 清单，可并行）**：T-20…T-37 无相互依赖，唯一顺序约束：T-30 与 T-28/T-29 同文件（sig/resolve.go），建议同一批；T-33 与 T-34 同文件（config_write.go），建议同一批。

---

**立项 37 条 / 驳回 2 条 / 挂起 10 条（另有 2 条修复动作与 T-01/T-06 同源并入，合计 51 项发现）。驳回率 4%，原报告可靠性无系统性问题。**

> 复核勘误：审计报告 §3 的 Low 汇总计数「28 项」漏列了 D4-7（Load 无文件大小上限——领域四详证中存在、汇总表未计入）；Low 发现实为 30 条（28 行中「D7-11+D8-4」为两项）。本计划按领域详证全量处理，两项均已立项（T-27/T-30/T-31）。
