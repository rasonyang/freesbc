# FreeSBC 面向公网部署的深度安全代码审查报告

- 审查日期：2026-08-26
- 审查分支：`master`
- HEAD commit：`b998f0883c363f4890f950f576d9de99d52c5630`（`chore: ignore local .superpowers/ tooling state`，2026-07-20）
- 工作区状态：干净（`git status --short` 无输出）
- 审查者：Go / VoIP 安全审计（自动化 + 人工复核）
- 仓库自身规则文件：CLAUDE.md / AGENTS.md / SECURITY.md / CONTRIBUTING.md / .claude/ 均**不存在**，无规则冲突；docs/superpowers/ 为开发计划文档（非安全规则）。
- 授权：仓库所有者授权本次审查。只读审查 + 本地验证，未修改任何生产代码。

> 结构说明：§1–§3 为最终结论（阶段 F 整理版）；§4（自「阶段 A 基线」起）为过程记录与各领域详证（按子代理完成顺序嵌入，非按编号排序）；§5–§10 为纵深防御、命令记录、覆盖范围、证据缺口、整改计划与测试清单。

---

# 最终报告（阶段 F 整理版）

## 1. 执行摘要

对 FreeSBC（master @ b998f088，17,320 行 Go 含测试）做了面向公网部署的全量安全审查：8 个领域并行深度审查 + 主代理对全部 High 的逐行复核与跨模块利用链推演；sipgo v1.4.3 与 pion/sdp v3.0.19 源码经官方 tag 下载后本地逐行核对（证据可复查，存于 /tmp/freesbc-audit/）。本机无 Go 工具链，全部构建/测试/扫描命令如实记录为跳过（见 §6），所有结论为源码级静态验证。

**总体判断**：这是一个工程质量显著高于典型开源 SBC 起步项目的代码库——配置面（strict YAML、${ENV} 纪律、原子写回、fail-closed 热重载）、密码学材料处理（SDES 密钥生命周期、crypto/rand、不跨腿）、B2BUA 资源回收路径（全部错误路径核实无泄漏）、头级拓扑隐藏（零头复制）都有扎实的实现与测试纪律。多个高价值攻击链被证据排除（XSS、CSRF、CRLF 注入、请求走私、跨呼叫 BYE 劫持、redaction 泄密、nft 命令注入）。

**但公网部署尚不安全**。问题集中在两个结构性主题：

1. **未认证资源耗尽面（F-01/02/03/05 四项纯未认证矢量 + F-06 peer 源端口耗尽）**：防护平面（shield）挂在 handler 层，而 sipgo 传输/事务层存在多个先于、或绕过 shield 的无界资源消耗点——UDP 连接池按唯一源无界增长（先于一切防护）、TCP 流式解析缓冲无界、scanner-UA 触发的 ban 在限速之前（每包一次 nft fork/exec + 无上限 ban 表 + Warn 日志洪泛）。任一矢量都足以让未认证攻击者 OOM/拖垮同进程的媒体面。
2. **信任与封禁决策绑定 UDP 源地址（体系性）**：peer 身份=源 IP（UDP 伪造即完整 peer 信任→盗打），ban 对象=声称的源 IP（伪造 1 个包即可把任意第三方 IP——包括系统 DNS 解析器——打入内核级全协议 1h 黑洞且无解除手段）。默认配置（udp://0.0.0.0:5060 + nftables:auto）在这两点上都是最不利组合。

另有跨租户隔离缺陷（refresh re-INVITE 无 dialog 校验可探得他腿 SDES master key）、SRTP 防重放未启用（RFC 3711 MUST 违约，仓库测试自认）、TLS 凭据面缺失（入向恒自签、出向无信任锚可配）等 14 项 Medium。

**已确认漏洞计数：High 7、Medium 14、Low/纵深防御/待验证 28**（详见 §3 汇总表与 §4 各领域详证）。

## 2. 发布结论

### **阻止公网部署（当前状态）**

在以下「立即整改」项（§9）完成并验证前，不应将 FreeSBC 直接或间接（仅靠默认 shield）暴露于不可信网络。核心阻断理由：6 个远程 DoS/服务中断矢量（F-01–F-06：其中 F-01/02/03/05 完全未认证，F-04 仅需 UDP 源伪造能力，F-06 需 peer 源 IP）+ 伪造源 ban 可内核黑洞任意第三方 IP（含自身 DNS 解析器）+ UDP 下 peer 身份可伪造（盗打，F-07）。

### 有条件部署的前置条件（全部满足后可评估放行）

1. **信令面**：公网仅暴露 tcp/tls 监听（或上游 ACL 白名单 + uRPF）；或对入向 INVITE 启用 digest 质询。
2. **资源面**：修复 F-01/F-02/F-03/F-05（前置过滤或池上限、TCP 连接上限+超时、ban 路径节流与上限）。
3. **封禁面**：UDP 单包判定降级为仅内存 ban；nft 规则限 SIP 端口；提供 unban；nftables 默认 off（显式 opt-in）。
4. **Admin 面**：仅绑 loopback（或加 TLS/反代 + 失败限速 + 非 loopback 启动强告警）。
5. **媒体面（若启用 SRTP）**：启用防重放（F-09）+ 信令信道可验证性（F-13：可配真证书）。
6. **运行环境**：以 CAP_NET_BIND_SERVICE[+CAP_NET_ADMIN] 非 root 运行（见 D8-6 的 systemd 样例建议）；配置文件 0600。
7. 多租户场景（多个互不信任 peer）：必须先修 F-08。

## 3. 发现汇总表（按严重度；F-xx 为合并后编号，详证见 §4 对应领域节）

### High（7 项——全部远程可达；其中 4 项完全未认证，F-04 仅需 UDP 源伪造能力，F-06/F-07 需 peer 源 IP）

| 编号 | 合并自 | 标题 | 攻击者 | 一句话影响 | 置信度 |
|------|--------|------|--------|------------|--------|
| F-01 | D6-1+D1-12 | sipgo UDP 连接池按唯一源无界增长（先于解析、先于 shield） | 未认证（IPv6 /64 无需伪造） | 10k pps × 1h ≈ 4-6GB 不回落 → OOM 全部呼叫中断 | High |
| F-02 | D1-3+D6-5 | SIP TCP/TLS：无连接上限+无读/空闲超时+流式缓冲无界累积 | 未认证 | fd/goroutine 耗尽 + 每连接 1:1 内存 → 稳定 OOM | High |
| F-03 | D7-1+D6-2+D1-6+D6-10 | scanner-UA ban 在限速之前：未节流 nft fork/exec 风暴 | 未认证（唯一源） | 数千并发 nft 进程 → CPU/PID/内存耗尽 + Warn 日志洪泛 | High |
| F-04 | D7-2+D1-6 | 伪造源 UDP ban 注入：任意第三方 IP 内核级全协议 1h 黑洞 | 需 UDP 伪造（1 包/小时） | 打黑洞系统 DNS 解析器 → 出站解析全超时 → 路由瘫痪；无解除手段 | Med-High |
| F-05 | D7-3+D6-3 | banList 无容量上限（prune 只清过期项） | 未认证（唯一源+scanner UA） | 1h 窗口数千万条目 → 数 GB → OOM | High |
| F-06 | D1-1+D5-6/X3 | 无认证 INVITE → 媒体端口池耗尽 + 真实运营商外呼 | peer 源 IP（可 UDP 盲伪造） | 合法呼叫 503 + **toll fraud**（B-leg 先 ACK、盲伪造即 ~32s-5m 计费通话）+ 自环放大 | High |
| F-07 | D1-2+D2-1 | SIP 身份=源 IP、无质询：UDP 伪造源 IP = 完整 peer 信任 | 需 UDP 伪造或恶意 peer | 盗打（经出局路由）+ 限速全免；TCP/TLS 不受影响 | High |

### Medium（14 项）

| 编号 | 合并自 | 标题 | 一句话影响 |
|------|--------|------|------------|
| F-08 | D5-2+X1+D1-10 | refresh re-INVITE 仅按 Call-ID 匹配、无 dialog tag 校验 | 恶意/被攻陷 peer 可探测取得他腿 200 OK 应答（**含 SDES master key**）→ 配合嗅探/UDP 伪造解密与注入媒体；多租户场景按 High 处置 |
| F-09 | D5-1 | SRTP/SRTCP 防重放未启用（pion 默认 no-replay，仓库测试注释自认） | 违反 RFC 3711 MUST；在路径重放有效媒体注入 |
| F-10 | D6-4+D1-7 | 事务层 shield 盲区：杂散 response 每包 goroutine+Info 日志、解析失败全字节 Error 日志、畸形请求主动 400 | 未认证日志洪泛（磁盘耗尽）+ 打破「未知源静默」承诺 + 1:1 反射探测 |
| F-11 | D1-4+D5-5 | SDP relay 段透传 a=candidate/fingerprint/ice-*/o= 会话标识 | 内网拓扑跨 SBC 泄露（拓扑隐藏承诺落空）+ ICE 端点互操作故障 |
| F-12 | D1-5 | 裸 LF 头注入：From DisplayName/User、Request-URI user 透传不清洗 | 对宽松 SIP 栈=向运营商注入任意后续行（头注入/走私）；CR/CRLF 已排除 |
| F-13 | D2-3+D1-11+X2 | TLS 凭据面缺失：入向恒自签（无证书/mTLS 配置）+ 出向无信任锚可配 | 主动 MITM 可读/换 SDES 密钥；自签运营商被迫退回明文；启用 SRTP 时实际影响 High |
| F-14 | D3-3+D2-4+D6-7 | Admin：明文 Basic+无失败限速+无 Authorization 头也跑满 bcrypt | 暴露时=High：嗅探→/api/config/raw 全部 SIP 明文凭据→完整盗打链；未认证 CPU-DoS 同进程放大 |
| F-15 | D4-1 | admin 凭据/监听不随热重载生效 | 口令轮换后旧口令重启前持续有效（吊销缺口） |
| F-16 | D2-2 | allowed_ips 无宽度/非空/规范性校验（0.0.0.0/0 合法） | 误配即开放盗打中继（叠加 F-07） |
| F-17 | D7-4 | 全链路缺 IP 规范化（Unmap）；ban 落 banned6 永不匹配 | 双栈监听 fail-closed 断呼 + 内核 ban 静默失效 + 表项双份 |
| F-18 | D3-1 | 敏感管理响应无 Cache-Control: no-store | 含明文凭据的原始配置落盘浏览器缓存 |
| F-19 | D6-6 | peer 限速豁免 + TerminateGracefully 阻塞 ≤32s | 伪造 peer 源 INVITE 洪泛 → 160 万并发 goroutine → 数十 GB |
| F-20 | D2-5 | 出向 digest 质询参数全由远端控制、Authorization 可离线字典攻击 | 非 tls peer 的口令可被被动捕获者爆破；无 qop 时 REGISTER 可重放 |
| F-21 | D8-3 | DNS 信任链无加固（无 DNSSEC/pinning/地址类别告警） | peer 域名接管 → 重定向 B 腿 → digest 应答+SDES 密钥收割（tls peer 可被 CA 证书绕过，无 pinning） |

### Low / 纵深防御 / 待验证假设（28 项，详证见各领域节）

**Low 已确认（11）**：D1-8（onOptions/onAck/onBye/onNoRoute 无 panic 恢复+缺 To/From 头 nil-deref 证据）；D3-4（/healthz keep-alive 军团）；D4-3（PUT 权限继承 0644）；D4-5（无目录 fsync、symlink 被 rename 替换）；D4-8（fsnotify 静默死亡）；D5-4（watchdog 认证前刷新 lastRx→rtp_timeout 可无限续期）；D6-9+D1-9+D2-6（Call-ID 键控三表碰撞→kick 失效/列表失真）；D7-6（nft 模式热重载不生效）；D7-7（nft 表无实例隔离互删）；D7-9（dropUnidentified 每包 Info 日志）；D8-1（DNS 无超时/无 singleflight/负缓存满 TTL）。

**纵深防御（12）**：D3-2（无 CSP/nosniff/XFO）；D5-3（strict 仅 IP arming+无 SSRC/PT 校验）；D5-7（RTCP 明文透传 CNAME）；D6-8→并入 F-06（无 max_calls）；D7-5（shield 在 handler 层）；D7-8（nft 走 PATH）；D7-10（sipsak 等合法工具误杀 1h）；D8-5（无 CI/SBOM/签名；CVE 需 govulncheck 佐证）；D8-6（无降权、实际需 root 级能力）；D8-7（配置文件权限不检查）；D2-7（SSRF-by-config）；D4-4（PUT TOCTOU）。

**配置风险（2）**：D4-6（0.0.0.0 admin+bcrypt 无 cost 下限）；D7-11+D8-4（rate 无上限、<1s ban 截断 "0s"、tls 回退恒 5060）。

**待验证假设（3）**：D4-2（goccy 别名炸弹→fatal 栈溢出/OOM，机制已源码核验、运行时未证）；D8-2（SRV "." 与 port 0 端点，已证有界不 panic）；D3-5（无上限 Call-ID 进 /api/calls）。

## 4. 过程记录与各领域详细发现

> 本节含：阶段 A/B/E 过程记录 → 领域三、五、七、四、六、八、一详证 → 阶段 D 数据流 → 领域二详证（按子代理完成顺序嵌入）。D 系列编号即 §3 汇总表的合并来源；每条发现按第 4 节格式（严重度/置信度/类型/CWE/行号/链路/影响/修复/回归）呈现，Low 项为压缩要点（全文在 /tmp/freesbc-audit/domain-*-notes.md）。

### 阶段 A 基线

（见本报告首部元信息块：分支/HEAD/工作区/日期）

## 阶段 B — 架构与信任边界模型

### 模块结构（17,320 行 Go，含测试）

```
main.go        入口编排（run/check）
config/        YAML 解析(Loader/Parse)、${ENV}展开、校验、Store(atomic.Pointer)、fsnotify 热重载
sig/           sipgo 装配(UDP/TCP/TLS)、identify(源IP→peer)、bridge(B2BUA)、routing、sdp重写、
               register(出向REGISTER+digest)、resolve(DNS SRV)、health(端点冷却)、timers(RFC4028)、
               tlscert(自签TLS)、crypto(SDES)
media/         portpool(RTP端口池)、relay(UDP转发+latching)、session、srtp(pion SRTP↔RTP)
shield/        ratelimit(每IP令牌桶)、scanner(UA指纹)、banlist(内存封禁+nftables联动)、shield(组装)
admin/         server(Basic Auth中间件)、api(JSON状态)、config_write(PUT /api/config 原子写回)、
               metrics(私有Prometheus registry)、webui(embed SPA)、redact
callstate/     内存呼叫注册表
```

### 外部入口清单

| # | 入口 | 协议/端口 | 绑定来源 | 认证 | 首个解析点 | 解析前限速? |
|---|------|-----------|----------|------|------------|--------------|
| E1 | SIP UDP | UDP `listen.sip`（默认/示例 `udp://0.0.0.0:5060`） | 配置文件 | 源 IP ∈ peer.allowed_ips（`sig/server.go:363` identify，信任边界=传输层 Source()，非 Via/From） | sipgo 传输层解析完整 SIP 消息 → `withShield`→handler（`sig/server.go:377`） | **否**——限速在 handler 入口（shield.Check），但 sipgo 完整解析发生在其**之前** |
| E2 | SIP TCP | TCP 同上 | 同上 | 同上 | 同上（`bindListener`→`tl.ServeTCP`，`sig/server.go:328`） | 否（同上） |
| E3 | SIP TLS | TLS `tls://…:5061` | 同上 | 同上 + TLS（**始终自签**，`sig/tlscert.go:21`，无证书配置项） | 同上（`sig/server.go:335`） | 否（同上） |
| E4 | RTP/RTCP | UDP `listen.media.port_range`（示例 16384-32768） | 配置文件 | 无（首包 latching + strict/loose） | `media/relay.go` RTP 头解析 | 否（媒体面无 shield） |
| E5 | Admin HTTP | HTTP `admin.listen`（示例注释 127.0.0.1:8080，**可配 0.0.0.0**，无 TLS） | 配置文件 | bcrypt Basic Auth（`admin/server.go:100`）；**`/healthz` 免认证**（`admin/server.go:65`） | net/http（ReadHeaderTimeout=5s，`admin/server.go:80`；无 Read/Write/IdleTimeout、无 MaxHeaderBytes 定制） | 否（bcrypt ~50-100ms/次，本身即暴力破解减速器） |
| E6 | 配置文件 | 本地文件 + fsnotify | CLI `-c` | 无（本地文件权限） | `config/loader.go`（goccy/go-yaml） | 否 |
| E7 | nftables | 本地 exec | `shield.nftables` 模式（auto/on/off） | 无（外部命令） | `shield/nftables.go` | — |
| E8 | DNS 出站 | UDP/TCP 53 → net.Resolver | peer.address | — | `sig/resolve.go`（SRV+A/AAAA，缓存 srv_cache_ttl） | — |
| E9 | 出向 SIP | UDP/TCP/TLS → peer 端点 | peers[].address | digest（401/407 挑战） | `sig/register.go`/`sig/b2bua.go`（digest 客户端为 sipgo 自带 DoDigestAuth/WaitAnswer；icholy/digest 仅测试用；sig/crypto.go 为 SDES 与 digest 无关——领域二更正） | — |

### 信任边界结论

1. **SIP 面（E1-E3）完全靠源 IP 鉴别 peer**——`allowed_ips` 匹配即获得该 peer 的全部入呼权限（无 SIP 级摘要质询）。`IdentifyPeer`（`sig/identify.go:17`）按字典序取首个匹配。`AllowsIP` 的规范化（IPv4-mapped IPv6 等）是关键校验点。
2. **shield 在 handler 层而非传输层**（`sig/server.go:377-386`）：sipgo 已完成完整 SIP 解析、事务创建后才调 `shield.Check`。解析成本不受限速保护（领域一/六核查点）。
3. **Admin 面（E5）单端口承载** WebUI(`/`)、`/metrics`、`/api/*`（含 PUT /api/config 原子写回、DELETE /api/calls/{id}），统一 Basic Auth；`/healthz` 例外。写回路径 `admin/config_write.go` 限额 1 MiB、If-Match 乐观并发。
4. **媒体面（E4）无应用层限速**，安全依赖 latching 语义（strict 默认：首包须来自 SDP 信令 IP；relatch 仅经 SIP 状态机授权——`Relatch` 调用点是话务劫持审查核心）。
5. **TLS 恒为自签**（`sig/server.go:335` + `sig/tlscert.go`）：信令面 TLS 无对端可验证性 → SDES 密钥的机密性依赖一个不受认证保护的信道（交叉分析重点）。
6. 配置为唯一真相源：本地非特权用户若可写配置文件即完全控制 SBC（expected，但检查文件权限默认值与写回权限继承 `admin/config_write.go:113-116`）。

## 阶段 E — 验证命令及实际结果

在 `/home/rason/freesbc` 于 2026-08-26 执行，结果如下（**全部如实记录**）：

| 命令 | 实际输出 | 结论 |
|------|----------|------|
| `go build ./...` | `go: command not found`（exit 127） | **跳过：本机未安装 Go 工具链**（PATH 与全盘搜索均未找到 go/gofmt；无 /usr/local/go、无 snap、无 dpkg golang） |
| `go vet ./...` | 同上（exit 127） | 跳过，原因同上 |
| `go test ./...` | 同上（exit 127） | 跳过，原因同上 |
| `go test ./... -race` | 同上（exit 127） | 跳过，原因同上 |
| `govulncheck ./...` | `govulncheck: command not found`（exit 127） | 跳过：未安装，按约束不安装 |
| `gosec ./...` | `gosec: command not found`（exit 127） | 跳过：未安装，按约束不安装 |

补充环境事实：无 `GOMODCACHE`（~/go/pkg/mod 不存在）、仓库无 vendor/ 目录 → 第三方依赖源码**初始不可读**。（更正：领域一/六随后将 sipgo v1.4.3 与 pion/sdp v3.0.19 官方 tag 源码下载至 /tmp/freesbc-audit/ 本地副本，此后所有 sipgo/pion-sdp 内部结论均基于真实源码逐行核对——见领域六节首；goccy/go-yaml 与 pion/srtp 由对应子代理在上游源码上核验并标注【源码核验】。）

### Fuzz 覆盖检查（可本地验证部分）

`grep -rn "func Fuzz" --include='*.go' .` → **零匹配**：仓库当前没有任何 go fuzz target。

## 领域三发现（子代理返回 + 主代理复核）

> 方式：纯静态（无 Go 工具链）。admin/ 全部文件含 webui/index.html 全 522 行逐行读完。主代理已对 D3-3 的 bcrypt 无条件执行（admin/server.go:102-105）、D3-1 的响应头缺失（config_write.go:64-79）亲自复核确认。

### [D3-1] 敏感管理端响应缺少 Cache-Control: no-store（原始配置可落盘浏览器缓存）
- 严重度：Medium / 置信度：High / 类型：已确认漏洞 / CWE-525
- 受影响文件和行号：admin/config_write.go:64-79（/api/config/raw 仅设 Content-Type+ETag）；admin/api.go:11-14,62-64；admin/webui.go:14-22（反证：admin 包全部 Header().Set 仅 Content-Type/ETag/Allow/WWW-Authenticate，全仓库无 Cache-Control）
- Source→sink：os.ReadFile(cfgPath)（config_write.go:70）→ 未 redacted 原文直出（:78，可含字面量明文 trunk 密码）→ 带 ETag 无缓存头 → 浏览器磁盘缓存持久化；Basic Auth 无登出。
- 影响：完整配置（含明文密码，若操作员未用 ${ENV}）留驻磁盘缓存，可被后续使用同一系统账户者读取。
- 修复：recoverMW 统一注入 Cache-Control: no-store。回归测试：断言全部敏感路由带 no-store。

### [D3-3] 认证无限速/锁定 + 无 Authorization 头也执行 bcrypt ⇒ 未认证 CPU-DoS 与无限在线爆破
- 严重度：Medium / 置信度：High / 类型：已确认漏洞（前置：admin.listen 绑非 loopback；示例默认注释 admin 并写明 bind PRIVATE） / CWE-307(+CWE-770)
- 受影响文件和行号：admin/server.go:100-112（无计数/延迟/封禁）；server.go:104（bcrypt 无条件执行，连无 Authorization 头的请求也跑完整 bcrypt）；server.go:80（无连接上限）；config/validate.go:174-176（只要求合法 bcrypt 哈希，不设最低 cost——cost 4 合法）
- 攻击链：shield 只覆盖 SIP（唯一调用点 sig/server.go:381），admin 401 从不触发封禁 → 未认证请求每条耗费 bcrypt（cost10≈60-130ms/次，文献值）→ 10-16 并发饱和 1 核且与 SIP/媒体面同进程（main.go:90-135）；在线爆破速率仅受 CPU 约束，无失败锁定；无 TLS 选项（schema.go:115-123）→ 公网绑定时凭据可被在途窃听。
- 修复：401 加 per-IP 限速并把 admin 失败接入 shield；缺 Authorization 头直接 401 跳过 bcrypt；强制最低 cost；支持/文档化 admin TLS。
- 主代理复核：admin/server.go:102-105 确认 userOK/passOK 均无条件计算 ✔

### [D3-4] http.Server 未设 Read/Write/Idle Timeout 与连接上限（部分缓解，1 个已确认低危向量）
- 严重度：Low / 置信度：High（缺失事实）/ Medium（部分论证）/ 类型：纵深防御 + 已确认低危向量（/healthz keep-alive 军团：免认证免限速 + 无连接上限，server.go:65,80） / CWE-400
- 位置：admin/server.go:80（仅 ReadHeaderTimeout=5s）。慢 body PUT 需先过认证（config_write.go:87 在 requireAuth 后）；未认证最大响应仅 /healthz 19 字节。
- 修复：显式 Idle/Read/Write Timeout；/healthz 纳入轻量限速或加连接上限。

### [D3-5] 入站 SIP Call-ID 无长度限制即进 registry 与 /api/calls（待验证假设）
- 严重度：Low / 置信度：Medium / 类型：待验证假设
- 链：Call-ID 原样取值（sig/b2bua.go:1350-1355，无长度校验）→ callstate.Call.ID（b2bua.go:303-308）→ registry.Add（:326）→ /api/calls JSON（api.go:41）。前置条件高（需 allowed_ips 源、呼叫接通、受媒体池约束）。修复：SIP 入口限 Call-ID 长度；/api/calls 截断输出。

### 领域三纵深防御（非漏洞）
- [D3-2] 无 CSP / X-Frame-Options / X-Content-Type-Options（admin/webui.go:20、config_write.go:76；当前无注入链可达，仅纵深）CWE-693。

### 领域三已排除的高价值可疑点（要点，全文见 /tmp/freesbc-audit/domain-3-notes.md）
1. **存储型 XSS——已验证不可达**：index.html 全部动态渲染用 createElement+textContent（:365-373,390-403,348-356,447,437）；仅 4 处 innerHTML 且实参为静态字面量（:360,362,385,387）；无 eval/insertAdjacentHTML/document.write/on* 赋值。**SIP Call-ID→XSS→PUT /api/config 接管链不成立**。Go json 默认 HTML-escape 另加一层。
2. **CSRF/CORS——不可利用**：零 CORS 头；PUT/DELETE 必触发预检且预检请求无凭据 → 401 阻断；GET raw 受同源策略保护；Basic Auth 非 Cookie。
3. **DNS rebinding**：Host 不校验属实（server.go:63-75），但 Basic Auth 凭据按真实 origin 键控不随 rebinding 迁移 → 敏感路由 401。建议 Host 白名单作纵深。
4. Prometheus 标签注入/高基数——排除（peer/reason/version 全部非攻击者可控；/metrics 在认证后）。
5. redaction 完备（redact.go:20-22,31-33 有测试；秘密字段仅两个且均覆盖）。
6. PUT 400 回显不泄密（YAML 源行来自提交者自己的 body；${ENV} 错误只回显变量名）。
7. handleKickCall 无注入面；/healthz 仅 {"status":"ok"}；WebUI 无外部资源/eval。

## 领域五发现（子代理返回 + 主代理复核/合并）

> 方式：本地代码 + 仓库测试断言 + 上游 pion/srtp v3.0.12、sipgo v1.4.3 源码离线核对。D5-2 与主代理链 X1 独立收敛（互为佐证）；D5-6 与主代理链 X3 合并。

### [D5-1] SRTP/SRTCP 防重放未启用（pion 默认 no-replay，未传任何 ContextOption）
- 严重度：Medium / 置信度：High / 类型：已确认漏洞 / CWE-294、CWE-358
- 受影响文件和行号：media/srtp.go:52（CreateContext 无选项）；media/srtp_relay_test.go:11-13（**仓库测试注释自认** "CreateContext defaults to NO replay protection… resending decrypts every time"）；docs/superpowers/specs/2026-07-17-m5-srtp-sdes-design.md:173（设计声明 replay resistance，未兑现）
- 上游证据：pion/srtp v3.0.12 CreateContext 默认注入 SRTPNoReplayProtection()/SRTCPNoReplayProtection()；nopReplayDetector.Check 恒放行。
- 链路：重放密文 → 过 latch（IP:port 匹配）→ unprotect 认证解密成功（重放不改变有效性）→ re-protect 转发 → 对端收到有效重复媒体。认证标签仍防伪造，但 RFC 3711 §3.3.2/§3.4.2 接收方防重放为 MUST。srtp=optional/required 每条腿均受影响。
- 前置：在路径捕获（无需密钥）。
- 修复：NewSRTPContext 传 srtp.SRTPReplayProtection(64), srtp.SRTCPReplayProtection(128)；回归：重放第二次断言 drop（现有 pumpTransform 重试泵依赖 no-replay，需同步调整）。

### [D5-2/X1 合并] in-dialog refresh re-INVITE 仅按 Call-ID 匹配、不校验 dialog tag → 已识别 peer 可探测取得在用腿的 SDES master key
- 严重度：Medium（条件满足时接近 High，见升级说明）/ 置信度：High / 类型：已确认漏洞 / CWE-863
- 受影响文件和行号：sig/b2bua.go:127（仅要求 To-tag 存在非空，从不比对值，也不查 From-tag——RFC 3261 §12.2.2 三要素缺二）；:128（唯一匹配=Call-ID 查 callSDPStore，sig/callsdp.go:42-72）；:139（200 OK 原文回 entry.answer——SRTP 腿含 SBC 本腿出向 master key）；sig/timers.go:76-81,102-112（门闩：Session-Expires + body 与 compare 去 o= 后逐字节相等）；sig/server.go:363-369 + sig/identify.go:17-30（前置 identify 只验源 IP 属**某个** peer，非该 dialog 的 peer）；shield/shield.go:74（已配置 peer 豁免全部限速——探测 oracle 可全速运行）
- Source→sink：对端 INVITE（To-tag+Session-Expires+伪造 compare SDP）→ callSDP(callID) 命中 → tx.Respond(200, entry.answer)
- 可利用场景（主代理与子代理合并评估）：
  - 直接方（原 dialog 参与者）已知 key，无增量；
  - **第三方已配置 peer（恶意/被攻陷的跨租户对端）**：G.711 offer SDP 高度可预测（o= 行被剥离不参与比较），未知量仅媒体 IP:port（~2^15）；Call-ID 若可见/可猜 + 无限速豁免 → 高速 oracle 爆破（200 vs 501）→ 取得该腿 SDES master key → ① 配合嗅探解密该腿媒体；② **配合 UDP 源伪造（冒充该腿媒体地址 IP:port）实时注入任意音频**（latch 只查 IP+port，SRTP auth 用已知 key 可通过）。
- 升级说明：披露面（SRTP master key）+ 注入面（话务内容注入）达到 High 影响档，但前置条件为「攻击者本身是已配置 peer 或可长期伪装其源 IP」，故按跨租户隔离缺陷定 Medium，多租户运营时应按 High 处置。
- 修复：in-dialog 分支用 sip.DialogIDFromRequestUAS/UAC（Call-ID+双 tag）对照腿建立时记录的 dialog ID，不符回 481。回归：另一 peer 源 IP、Call-ID/compare 正确但 tag 错误 → 481 且不回 answer。
- 主代理复核：b2bua.go:127-150、timers.go:76-112、callsdp.go 逐行核实 ✔（对比：BYE 路径 onBye 走完整 dialog 匹配，有 tag 保护——证明该缺口是实现遗漏而非设计取舍）

### [D5-4] watchdog 在 SRTP 认证前刷新 lastRx（rtp_timeout 可被垃圾包无限续期）
- 严重度：Low / 置信度：High / 类型：纵深防御/规范偏差
- 位置：media/relay.go:45（lastRx.Store 在 :50-60 unprotect 之前）；规范 docs/superpowers/specs/2026-07-17-m5-srtp-sdes-design.md:166-170 顺序相反。
- 影响：知悉 latched IP:port 者可用不过认证的垃圾包保活，半开会话绕过 rtp_timeout（默认 5m）回收 → 放大 D5-6 的端口占用时长。修复：lastRx 移至两步 crypto 成功后。

### [D5-5] 拓扑隐藏缺口：relay 的 audio m= 段保留对端全部非 crypto 属性（a=candidate 等）
- 严重度：Low / 置信度：High / 类型：信息泄露 / CWE-212
- 位置：sig/sdp.go:176-190（rewriteSDPCrypto "keep everything except crypto/rtcp"）、:69-73（rewriteSDP）；对比 declined 段属性被清空（:198-200）。
- 影响：ICE candidate（常含 RFC1918 内网地址）跨 SBC 泄给另一腿，违背 sdp.go:38-44 自述的拓扑隐藏目标。建议属性白名单。

### [D5-6/X3 合并] 媒体端口池耗尽 + 伪造源 INVITE 占用端口并触发真实运营商话务
- 严重度：Medium（**→ 已升级为 High 并入 F-06**：领域一独立分析补充了自环放大与盲伪造计费链后，主代理裁决升级——见领域一节 [D1-1]）/ 置信度：High（代码路径）/ 类型：配置风险 + 已确认资源面 / CWE-400
- 位置：media/portpool.go:54-84 + media/session.go:140-165（每 INVITE 占 2 对=4 socket）；默认池 4096 对=2048 呼叫上限（config/schema.go:127-128）；**无任何 max_calls/per-peer 并发配额字段**（grep 全 schema）；占用时长 = ring 60s/目标（b2bua.go:817）或已应答无媒体 5m（watchdog，且 D5-4 可续期）；信令限速 20/s/IP 对 INVITE 生效但 identify 仅源 IP（server.go:363-369）→ **UDP 伪造 peer 源 IP 的 INVITE 每发 2 对端口占用可达 ≈5 分钟，并触发对真实运营商的出呼（计费/话费欺诈面——B-leg 在 A-leg ACK 之前即拨出并可被应答计费，b2bua.go:782-997）**。
- 回收路径逐条核实无泄漏：CANCEL（b2bua.go:902,589）、ring 超时（817/926）、全目标失败（594-602）、BYE（server.go:528-548→select 346-356）、RTP 超时、kick、panic（relay.go:105-112、b2bua.go:1341-1346）、Allocate 半失败（session.go:148-153）。
- 建议：per-peer 并发/端口配额；"应答后零媒体"独立短计时（30-60s）；评估对 UDP 首 INVITE 的反伪造措施（如 TCP/TLS-only 或 digest 挑战模式）。

### 领域五纵深防御（非漏洞）
- [D5-3] strict 仅按 IP arming：同 IP 抢注竞态 + 无 SSRC/PT/seq 校验（media/session.go:77-84 pre-latch 只比 IP——刻意的 NAT 容忍；:74-75 post-latch IP+端口都查）。明文腿为 RTP 固有弱点；SRTP 腿由 auth tag 兜底（同 IP 异端口注入失败）。建议文档化"同公网 IP 多租户需 srtp"。CWE-346、CWE-290。
- [D5-7] RTCP 明文腿逐字转发（SDES CNAME/SR/RR 泄对端标识与拓扑，media/relay.go:28-33,72-74）——SBC 常态，可选剥/重写 CNAME。

### 领域五已排除的高价值可疑点（要点，全文见 /tmp/freesbc-audit/domain-5-notes.md）
1. **re-INVITE 媒体重定向劫持——不可达**：Relatch 唯一生产调用点 b2bua.go:1306（仅 B 腿 2xx/18x，经客户端事务 Via-branch 匹配）；媒体变更 re-INVITE 一律 501（b2bua.go:149，测试断言）。设计文档"re-INVITE 授权 Relatch"表述超出实现（实现更保守）。
2. strict arm 前丢一切包——为真（session.go:77-84 + 测试）。
3. RTP 解析越界——明文路径不解析（纯字节复制）；SRTP 路径 pion 头非法 error→丢包 fail-closed。
4. SDES 密钥跨腿直通/declined 段泄露——防护到位（sdp.go:177-180,198-214；三个明文出向全部 rewriteSDPCrypto(...,nil)）。
5. 密钥暴露面干净：crypto/rand 30B 每腿每呼叫；无 key 入日志/metrics/admin API。
6. required 不降级（A 腿 488、B 腿 failover）；a=crypto 解析健壮（suite 白名单/严格 base64/30B/MKI 截断）。
7. dialog tag 熵：A 腿 To-tag=sipgo uuid.NewRandom（crypto 随机，上游核对）；B 腿 From-tag=crypto/rand 24hex。
8. 1500B 截断、loose 默认值、failover 陈旧上下文（原子指针）等——无安全问题。

## 领域七发现（子代理返回 + 主代理逐行复核全部 High）

> 主代理复核记录：shield.go Check 顺序（peer 豁免:74 → banned:77 → scanner ban:81-86 → 限速:87-92）、banlist.go:26-33（mutex 在 nft 调用前释放=无串行化）、nftables.go:39-41（同步 exec 无信号量）、:62-63（input 链全协议 drop）、:76-79（Is6 判 4in6 → banned6）、banlist/ratelimit/failCounter 三个 map 的无界性——全部亲自 Read 确认 ✔。

### [D7-1] scanner-UA ban 在限速之前：未节流的 nft fork+exec 风暴（无并发上限/队列/去重）
- 严重度：High / 置信度：High / 类型：已确认漏洞 / CWE-770、CWE-405
- 受影响文件和行号：shield/shield.go:81-86（scanner ban 先于 :87-92 限速）；shield/banlist.go:26-33（nft 调用在锁外，无并发控制）；shield/nftables.go:39-41,75-85（exec.Command(path,...).Run() 同步阻塞，无锁/信号量/队列）
- Source→sink：withShield（sig/server.go:377-386）→ Check → 非 peer → 未 ban → isScanner（UA 攻击者可控，sig/server.go:404-410）→ bans.ban → nftBackend.ban → fork+exec("nft","add","element",...) —— **全程未经过 rateLimiter.allow**。
- 可利用场景：唯一源 UDP 洪流（伪造源或僵尸网络）+ `User-Agent: friendly-scanner` → 每包一次 fork+exec（sipgo 每请求一 goroutine 各自阻塞）→ 数千并发 nft 进程 → CPU/PID/内存耗尽 + 每包一条 Warn 日志（shield.go:83）。前置：nft 激活（默认 auto：二进制存在+setup 成功即激活，通常 root 部署成立）。nft 未激活时退化为 D7-3。
- 修复：scanner 判定移到限速之后，或 ban 写路径单独全局限速（超限只写内存表）；nftBackend 加串行 worker+有界队列；同 IP 去重。回归：注入 run 记录器并发 ban 1000 IP，断言并发与总 exec 数上限。

### [D7-2] 伪造源 UDP ban 注入：任一非 peer IP 可被写入内核 nftables，全协议 1h 黑洞且无解除手段
- 严重度：High / 置信度：Medium-High（代码路径确定；利用依赖 UDP 源伪造能力） / 类型：已确认漏洞（设计缺陷） / CWE-290、CWE-345
- 受影响文件和行号：shield/shield.go:81-86（scanner 路径 **1 包即 ban**）；shield.go:116-126 + sig/server.go:418-429（auto-ban 路径 5 包）；shield/nftables.go:61-63（input 链规则无端口/协议过滤 → 全协议）；config/schema.go:159-161（默认 auto）
- Source→sink：伪造源=VICTIM 的单个 UDP OPTIONS（UA 含 sipvicious）→ `nft add element inet freesbc banned4 { VICTIM timeout 3600s }` → 内核丢弃来自 VICTIM 的**所有**入站包（任意协议端口）1 小时，且无 admin unban 端点（admin 全部路由只读+踢呼叫，admin/server.go:63-75），只能重启或手工 nft。
- 可利用场景（影响量化）：VICTIM=系统 DNS 解析器 → SBC 出站 DNS 响应被内核丢弃 → SRV/A 解析全部超时 → 路由瘫痪（稳定远程服务中断，每小时 1 个伪造包即可维持）；VICTIM=运维工作站/新运营商信令源/监控 → 同理黑洞。唯一豁免：peer.allowed_ips 内的 IP（伪造 peer IP 不会被 ban——顺序已验证）。
- 修复：UDP 上仅对完成过往返的源执行内核 ban（单包判定只做内存 ban）；内核规则限定 SIP 端口与协议；提供 admin unban/flush；nftables 默认改 off 或要求显式 on。
- 主代理复核：nftables.go:62-63 规则原文 `ip saddr @banned4 drop` 无 dport 限定 ✔；admin 无 unban 路由 ✔

### [D7-3] banList 无容量上限：唯一源洪水 → 内存耗尽（prune 只清过期项）
- 严重度：High / 置信度：High / 类型：已确认漏洞 / CWE-770
- 受影响文件和行号：shield/banlist.go:13-22,26-33（map 无上限）；:60-69（prune 仅删已过期；条目寿命=auto_ban.duration 默认 1h）；次要 shield/ratelimit.go:66-78（桶 map 分钟窗内无界）、shield/shield.go:188-202（failCounter 窗口内 append 无界）
- 根因：M6 规格（docs/superpowers/specs/2026-07-17-m6-shield-design.md:193）声称 bounded memory，实现的有界性取决于「新源注入速率 × Duration」这一攻击者完全可控的乘积。
- 可利用场景：伪造唯一源 + scanner UA（1 包/源，无限速）→ 10k/s 持续 → 1h 窗口内数千万条目（每条 ~100-150B）→ 数 GB → OOM；nft 激活时内核 set 同量级膨胀并叠加 D7-1。
- 修复：ban 表硬上限（如 64k；超限降级为 /24、/48 前缀聚合——运营商惯例）；nft set 配 maxsize；超限策略显式化并告警。回归：假时钟下 ban 超上限数量 IP，断言表大小被钳制。

### [D7-4] 全链路缺 IP 规范化（无 Unmap）：双栈监听下 peer 识别失效 + 内核 ban 写 banned6 永不匹配 + 表项双份
- 严重度：Medium / 置信度：Medium-High（netip/nftables 语义依标准库文档与领域知识；无 Go 工具链未能运行时复验） / 类型：已确认（规范化缺失）+ 配置风险 / CWE-706
- 受影响文件和行号：sig/server.go:391-401（sourceAddr 无 .Unmap()——全仓库 Unmap 仅 media/session.go:82）；shield/nftables.go:76-79（Is6() 对 ::ffff:a.b.c.d 为 true → 误写 banned6，元素串 `::ffff:x.y.z.w`，而真实 v4 包不评估 ip6 saddr → **内核封禁静默无效**）；config/types.go:96-99（监听 host 接受 ""——`udp://:5060` 是自然写法，Go 空 host 监听=双栈 [::] socket → v4 对端呈 4-in-6）
- 影响：① 双栈监听下 IPv4 peer 全部不被识别（netip 跨族 Contains=false，fail-closed → 呼叫全断，会立即暴露）；② 这些源的内核 ban 全部无效（内存层仍有效，日志无差别）；③ 同一 IP 的 v4/4in6 两形态是不同 map key → ban 表/桶/计数器双份额度。
- 修复：sourceAddr 返回前统一 Unmap()（或 Check/ban 入口）；校验层拒绝空 host 或文档强制单栈写法。回归：`Check(::ffff:203.0.113.10)` 对 allowed_ips 含 203.0.113.0/24 应豁免；ban argv 应选 banned4。
- 主代理交叉：与主代理独立验证一致（identify fail-closed 方向无绕过；本条补充了内核层失效与双份额度两个增量）。

### 领域七中低危（要点，全文见 /tmp/freesbc-audit/domain-7-notes.md）
- [D7-5] Medium（纵深）：shield 在 handler 层（sig/server.go:377-386），sipgo 完整解析成本不受保护；nft 缺席时已 ban 源每包仍付全量解析（nftables.go:28-49 auto 探测失败静默纯内存）。CWE-400。
- [D7-6] Low：shield.nftables 模式热重载不生效（构造时固定，shield.go:26-47；on→off 后仍写内核）。CWE-665。
- [D7-7] Low：nft 表名 `inet freesbc` 无实例隔离（nftables.go:56 无条件 delete table → 双实例互删/operator 同名表被删）。CWE-667。
- [D7-8] Low（纵深）：nft 经 PATH 解析无绝对路径配置（nftables.go:32,39-41；argv 本身无注入）。CWE-426。
- [D7-9] Low：dropUnidentified 每请求一行 Info 日志（sig/server.go:418-421）——1000 IP 僵尸网络 ≈2 万行/秒（~260GB/天）；对照 rate 分支仅 Debug，唯此处在 Info。CWE-400。
- [D7-10] Low：scanner 指纹含 sipsak 等合法运维工具（scanner.go:11-23）→ 单包 1h 内核黑洞且无解除（叠加 D7-2）。CWE-697。
- [D7-11] Low（含待验证）：rate_limit 数值无上限（types.go:132-135——"1000000/s" 合法 → failCounter 1.4GB/IP）；<1s ban 时长 nft timeout int 截断为 "0s"（nftables.go:80，nft 对 0s 行为未验证）。CWE-1284。

### 领域七已排除的可疑点（要点）
1. **nft 命令注入——已验证不可达**：无 shell；exec.Command argv 数组（nftables.go:39-41，全仓唯一 exec 点）；非常量 argv 仅 ip.String()（netip 规范化输出）与 Itoa 数字；表/链/集名全为编译期常量；测试断言精确 argv。
2. **ParseRateLimit 失败 fail-open（ratelimit.go:34-36 rate≤0 全放行）——已验证不可达**：Load→Parse→validate 拒绝无效串（loader.go:31-44、validate.go:145-147），热重载同走 Load；唯一入口是单测手工构造 Config。
3. 伪造 peer IP → shield 全豁免——属实但属 identify 域（见 D5-6/D2 领域），且顺序保证伪造 peer IP 不会使真 peer 被 ban。
4. PerIP=false 全局桶误伤——被限速的只有本就会被静默丢弃的非 peer 源；规格明示设计。
5. sourceAddr 失败绕过 shield——req.Source() 恒为 socket 地址，实际不可达。
6. 日志注入（UA 入 Warn）——SIP 头值无 CRLF（解析层约束），slog 引号转义。
7. Close 与在途 Check 竞态——defer 顺序经 wg.Wait 保证（server.go:216 vs :296）。

## 领域四发现（子代理返回 + 主代理复核）

> goccy/go-yaml v1.19.2 行为经上游源码核验（标【源码核验】）。**该领域总体结论：配置面设计良好——strict 解析（未知键/重复键均拒绝 ⇒ 拼错 allowed_ips 是 fail-closed）、ENV 缺失整份拒绝（无空密码 fail-open）、写回原样保留 ${ENV}、坏热重载保持旧配置、Store 单指针原子替换。未发现可被未认证远程攻击者利用的配置面漏洞。**

### [D4-1] admin 凭据与监听地址不随热重载生效：口令轮换后旧口令持续有效
- 严重度：Medium / 置信度：High / 类型：配置风险 / CWE-613、CWE-1188
- 位置：main.go:104,:127（`store.Current().Admin` 仅启动读一次固化进 admin.New）；admin/server.go:59,:80,:103-104（requireAuth 每请求用启动时凭据）；对照 api.go:63（GET /api/config 从 store 读新配置）；设计文档自认 docs/superpowers/specs/2026-07-17-m7-1-admin-api-metrics-design.md:177-179。
- 可利用场景：admin 口令疑似泄露，操作员经热重载/WebUI 更换 password_hash——GET /api/config 显示新配置、保存成功，但**旧口令重启前一直有效**（攻击者保有全部 admin 权限：读未脱敏 /api/config/raw、改路由、踢呼叫）。反向：删除整个 admin: 段也不会关闭 admin API。
- 修复：requireAuth 每请求从 store.Current() 取（bcrypt 本就 ~50ms/次无额外代价）；或检测 admin.auth/listen 变化即拒绝（409 提示需重启）或打高显著度 WARN。回归：热换 admin.auth 后旧凭据必须 401。
- 主代理复核：main.go:104-136 与 admin/server.go:59 确认 cfg 启动期固化 ✔

### 领域四中低危（要点，全文见 /tmp/freesbc-audit/domain-4-notes.md）
- [D4-2] Low（待验证假设，机制【源码核验】）：goccy 别名展开在 BytesUnmarshaler 字段（config/types.go:30,51,82 三个自定义标量类型）上无界——自引用别名 `&a [*a]` → formatAlias 无界递归 → **不可 recover 的 fatal 栈溢出**，进程连同在途呼叫一起死；别名炸弹 → OOM。前置=配置内容控制权（威胁模型内已等同控制 SBC），故 Low。修复（一行级）：加载前拒绝含锚点/别名的配置（SBC 配置不需要它们）。
- [D4-3] Low（本地威胁）：PUT 写回继承原文件权限位（config_write.go:113-116）——0644 配置含字面明文凭据时可被本地其他用户读取；无任何 chmod 指引。CWE-732。
- [D4-4] Low：PUT If-Match TOCTOU 与并发 PUT 竞态（config_write.go:97-117 无锁）——可信主体丢失更新，无越权。CWE-367。
- [D4-5] Low：writeFileAtomic 缺目录 fsync（耐久性非原子性——不会出现空/半文件）；cfgPath 为符号链接时 rename 替换链接本身（部署布局被悄悄改变）。
- [D4-6] Low（配置风险）：校验允许 admin.listen 绑 0.0.0.0 且无告警（validate.go:167-170；明文 HTTP Basic Auth）；bcrypt 无 cost 下限（:174-176，cost 4 合法）。CWE-668、CWE-916。
- [D4-7] Low：Load 无文件大小上限（loader.go:11-17 整读；PUT 路径已有 1MiB 上限）。
- [D4-8] Low：fsnotify Events 通道非正常关闭时 Watch 返回 nil、main 静默（reload.go:57-59 + main.go:78）——热重载静默死亡，运行配置永不变化但 PUT 持续 200。

### 领域四已排除的关键可疑点
1. 拼错 allowed_ips ⇒ 匹配所有源——**不成立**：yaml.Strict() 未知键整份拒绝（loader.go:33 + 测试）；allowed_ips 空 ⇒ AllowsIP 恒 false（fail-closed）。
2. 重复键覆盖——不成立：goccy 默认拒绝重复 map key【源码核验】。
3. 缺失 ${ENV} ⇒ 空密码——不成立：缺失/畸形整份拒绝（expand.go:116-124,37-39）。
4. 展开秘密落盘/入错误/入 API——不成立（写回原文；解析错误先于展开；redact 覆盖两个秘密字段）。
5. 坏热重载 fail-open/半更新——不成立（reload.go:73-78 保持旧配置；单 atomic.Pointer 整体替换）。
6. fsnotify 风暴——已缓解（200ms 防抖 + 目录监听 + tmp 文件按 basename 过滤）。
7. ReDoS——不成立（加载期编译、RE2 线性、组引用校验）。
8. transform CRLF 注入——未发现不可信路径（OutNumber 输入是已解析 SIP URI user，解析后无 CR/LF）。

## 领域六发现（子代理返回 + 主代理对全部 High 逐行复核）

> 关键证据升级：子代理将 sipgo v1.4.3 完整源码下载至 /tmp/freesbc-audit/sipgo-1.4.3/，全部 sipgo 内部结论基于真实源码。主代理已亲自复核 D6-1（transport_udp.go:177-184 + transport_connection_pool.go:108-118）与 D6-4（transaction_layer.go:18-20,165,190,214-226 + transport_udp.go:229）✔。

### [D6-1] sipgo UDP 连接池按「唯一源地址」无界增长——先于解析、先于 shield
- 严重度：High / 置信度：High / 类型：已确认漏洞（继承自依赖，FreeSBC 直接暴露公网） / CWE-770
- 受影响文件和行号：sip/transport_udp.go:177-184（readListenerConnection 对每个新远端地址 `t.pool.Add(rastr, conn)`，发生在 parseAndHandle 之前）；sip/transport_connection_pool.go:108-118（Add 只插入无淘汰；UDP 池项仅在监听器关闭时清除=进程生命周期永不删除）；挂接点 sig/server.go:324-358（bindListener → tl.ServeUDP，无任何前置过滤；sipgo 有 readFilter 钩子但 FreeSBC 未用）。
- 攻击者能力/前置：仅需向 5060/udp 发任意包（无需可解析 SIP）。IPv6 攻击者用自己 /64 内任意源地址即可（2^64 键空间，无需伪造）；IPv4 需无 uRPF 伪造。shield 完全看不到（Check 在 handler 层）。
- 量化：每项 ~100-180B。10k pps × 1h ≈ 3600 万项 ≈ 4-6 GB 不回落 → OOM，全部呼叫中断。
- 修复：上游补丁（池上限+LRU）；短期利用 sipgo readFilter 钩子做前置过滤，或 nftables 非白名单源早期 DROP。
- 主代理复核：源码逐行确认 pool.Add 无界且先于解析 ✔

### [D6-4] 事务层/传输层的 shield 盲区：杂散 response 每包一 goroutine+一日志；解析失败全字节 Error 日志；畸形请求主动回 400（打破「未知源静默」承诺）
- 严重度：Medium / 置信度：High / 类型：已确认漏洞（日志洪泛+指纹暴露+反射） / CWE-400
- 受影响文件和行号（均不经 withShield——它只包裹请求 handler，sig/server.go:219-223）：
  1. 任意 SIP response 包 → sipgo transaction_layer.go:133-146 每包 spawn goroutine → 无匹配 client tx → defaultUnhandledRespHandler（:18-20）每包 1 条 Info 日志；FreeSBC 的 sipgo.NewClient（sig/server.go:179）未设 UnhandledResponseHandler。
  2. 解析失败：transport_udp.go:229 `Error("failed to parse", "data", string(data))` —— **攻击者原始字节全文落 Error 日志**，每包一条（64KB/包 × 高速率 = 日志盘秒级 GB 级）。
  3. 可解析但缺 Via/CSeq：rejectMalformedRequest（transaction_layer.go:214-226）**主动回 400** —— 在 shield/identify 之前，任何未认证源都能拿到响应：破坏「未知源静默丢弃」承诺（sig/server.go:572-582 自述），并提供 ~1:1 反射。
- 换行注入已验证不可利用（slog TextHandler 对含换行值走引号转义）。
- 修复：NewClient 设 UnhandledResponseHandler（静默计数）；sipgo 日志降采样；上游修 parse 失败日志。
- 主代理复核：三处 sipgo 源码原文确认 ✔；此项同时修正了阶段 B 信任边界模型中「未识别源必获静默」的结论。

### [D6-5] SIP TCP/TLS 监听无连接上限、无空闲/读超时（Slowloris）——⚠️ 本条部分结论已被主代理推翻
- 严重度：Medium（**→ 与 D1-3 合并升级为 High=F-02**）/ 置信度：High / 类型：已确认漏洞 / CWE-400
- **主代理裁决（见领域一节首）**：本条原文「per-conn 内存有界（解析上限 64KB）」**不成立**——sipgo parser_stream.go:117-121 Write 无条件累积、:125-139 的 65535 上限仅在完整解析后检查、transport_tcp.go:227-240 对 partial 错误继续读 → 每连接内存无界。本条的「无连接上限、无超时」部分仍然成立。
- 位置：sig/server.go:324-345（裸 net.Listen + ServeTCP/ServeTLS）；sipgo transport_tcp.go:60-70（accept 无限制）、:135-143（无 SetReadDeadline/Idle，keepalive 注释掉 :108-116）。每条静默连接 = 1 goroutine + 1 fd + 池项，永不回收；fd 耗尽连带 UDP 与媒体端口。~~per-conn 内存有界（解析上限 64KB）~~ **已被推翻**：单条完整消息确有 65535 上限（parser.go:33、parser_stream.go:196-198），但慢喂不完整消息的跨读累积无界（D1-3，parser_stream.go:117-121）——问题同时是连接数与每连接内存。
- 修复：自包装 Listener 限并发/per-IP 连接数。

### [D6-6] peer 限速豁免 + 应答后 TerminateGracefully 阻塞：伪造 peer 源 IP 的 INVITE 洪泛钉住 goroutine ≤32s
- 严重度：Medium / 置信度：Medium（需伪造 peer IP 或恶意 peer） / 类型：已确认漏洞（条件性） / CWE-770
- 位置：shield/shield.go:72-76（peer 豁免一切限速）→ b2bua.go:188-190 应答 → sipgo server.go handleRequest → tx.TerminateGracefully → transaction_server_tx.go:165-182 `<-tx.Done()` 阻塞至 ACK 或 Timer H=32s（transaction.go:64）。每包 1 goroutine + 数 KB 事务：伪造 50k pps → 160 万并发 goroutine → 数十 GB。攻击者无需看到响应。
- 修复：对 peer 也施加宽松限速；per-peer 并发 INVITE 上限。

### [D6-9] Call-ID 跨呼叫键冲突（killers/registry/sdps 三表）
- 严重度：Low / 置信度：High / 类型：已确认漏洞（需 peer 重用 Call-ID） / CWE-667
- 位置：sig/server.go:98-110、b2bua.go:303-342（三集合均以 A-leg Call-ID 为键）。并发同 Call-ID 第二呼叫覆盖条目，先结束者 defer 误删后者 → 后者对 /api/calls 不可见且 KillCall 404。修复：键加 From-tag 或对重复 Call-ID 回 482。

### 领域六已合并条目
- D6-5（TCP 无连接上限/无超时；「每连接内存有界」结论被推翻）→ 与 D1-3 合并为 **F-02（High）**。
- D6-2（scanner ban 绕限速的量化与 failCounter 变体）→ 并入 [D7-1]/[D7-3]。
- D6-3（限速桶 map 无上限，稳态=近 1-2 分钟唯一源数，10k pps≈60-120MB）→ 并入 [D7-3] 次要面。
- D6-7（admin bcrypt 每请求全量验证+无 IdleTimeout+无连接上限）→ 并入 [D3-3]/[D3-4]。
- D6-8（无 max_calls，~68 INVITE/s×60s 占满端口槽位；setup 期呼叫不在 registry 不可 kick）→ 并入 [D5-6]。
- D6-10（nft exec 无超时且在热路径，nft 卡住时请求 goroutine 无限堆积）→ 并入 [D7-1]。

### 领域六已排除的可疑点（要点）
1. 静默丢弃导致事务表堆积——不可达（sipgo handleRequest 对未 finalize 事务立即 Terminate→drop）。
2. relay goroutine 泄漏/双 Close——排除（forward 随 socket Close 退出；Close 幂等 closeOnce；panic 路径关会话；onInvite 全资源有 defer）。
3. kick 与自然结束竞态/double-BYE——排除（select 单分支；cancel 幂等；registerKiller 先于 registry.Add）。
4. registrar 死锁/泄漏——排除（stopAll 先 cancel 后逐一等 done；unregister 2s 超时）。
5. TCP 每连接无界 body——排除（64KB 解析上限；连接数问题归 D6-5）。
6. 持锁阻塞 I/O——排除（ban 先解锁再 exec；DNS 在锁外；portpool 锁内仅 O(1)）。
7. failCounter 单 IP slice 无限增长——排除（默认配置第 5 包即 ban，banned 分支先行）。
8. store 快照撕裂——排除（atomic.Pointer 不可变快照）。

## 领域八发现（子代理返回 + 主代理复核）

> **该领域总体结论：供应链基本面扎实**——无 replace/exclude、go.sum 对全部 22 个依赖双哈希完整、零硬编码秘密（示例全用 ${ENV} 或被机制拒绝的占位符）、git 全历史无 sbc.yaml、embed 面干净（单文件、无外部资源）、exec 无 shell、无 unsafe/cgo、icholy/digest 仅测试导入不进交付二进制。**未发现 Critical/High。**
> **关键澄清（解决主代理链 X2）**：出向 TLS 证书校验默认开启——sipgo 全库无 InsecureSkipVerify，出向用零值 tls.Config（ServerName=hostname、系统 CA，transport_layer.go:129-132、transport_tls.go:24-31）。⇒ SDES over 出向 TLS 对持 CA 证书的对端是受保护的；链 X2 缩窄为「入向恒自签无证书配置项 + 无 pinning 能力」。

### [D8-3] 对端 DNS 信任链无加固（无 DNSSEC/pinning/地址类别告警）——DNS 控制可重定向 B 腿并收获 digest 应答与 SDES 密钥
- 严重度：Medium / 置信度：Medium / 类型：纵深防御（前置条件强） / CWE-345
- 位置：sig/resolve.go:54（系统默认解析器，明文 53、无 DNSSEC）；:97-104（SRV 结果直转端点，loopback/私网零告警）；b2bua.go:752-822（INVITE/WaitAnswer 携带 digest 凭据）；register.go:101（REGISTER digest 应答）；SDES 密钥明文进 B 腿。
- 分级：域名过期重注册/注册商攻破 → SRV 指向攻击者 → **digest 应答可离线爆破 peer 密码 + SDES 密钥泄露 + 话费欺诈**；tls peer 亦不免疫（域名持有者可取公共 CA 证书通过验证，无 pinning 可配）；在路 UDP53 投毒 → 同等重定向但 tls peer 握手失败（出向验证开启已核源码）。
- 修复：文档化 peer 域名防过期信任假设；出向 TLS 增加 CA/pin 配置项；解析到 loopback/link-local 记告警；运营侧本机递归启用 DNSSEC。

### [D8-1] SRV 解析无超时、无 singleflight、错误结果按满 TTL 负缓存
- 严重度：Low / 置信度：High / 类型：配置风险（可用性） / CWE-400
- 位置：sig/resolve.go:46,54（包级 net.LookupSRV 无 ctx）、:86-104（并发无去重、失败/空结果同 300s 入缓存）、调用点 b2bua.go:469（onInvite goroutine 内同步、不可被 CANCEL 打断）。
- 影响：DNS 抖动期每呼叫 goroutine 阻塞；缓存过期瞬间 N 并发=N 次查询；一次瞬时故障使该 peer 整 300s 只用裸主机名回退。修复：Resolver.LookupSRV(ctx)+WithTimeout、singleflight（x/sync 已是间接依赖）、失败短 TTL。

### 领域八中低危（要点）
- [D8-2] Low（待验证）：SRV 无语义校验——Target "."（RFC 2782 服务不可用）与 port 0 生成空 Host 端点（resolve.go:143-206）。**已用 sipgo 源码验证有界不 panic**，仅浪费尝试+冷却噪音。CWE-20。
- [D8-4] Low：DNS 回退端口恒 5060——transport:tls 应回退 5061（RFC 3263 §4.1；resolve.go:98-99）；REGISTER 路径 splitHostPortDefault(address,5060) 完全绕过 SRV resolver（register.go:390）。可用性问题（拨错端口），非降级。CWE-440。
- [D8-5] Low（纵深）：无 CI/Makefile/Dockerfile，发布无 -trimpath/SBOM/签名；CVE 离线评估：x/crypto v0.54.0（已知 CVE 均已远超修复线且仅用 bcrypt）、其余依赖离线无已知 CVE——**需 govulncheck 机器佐证**。CWE-1357。
- [D8-6] Low（纵深）：无降权逻辑；5060/5061+CAP_NET_ADMIN 实际要求 root 级——建议 systemd AmbientCapabilities 样例。CWE-250。
- [D8-7] Low（纵深）：Load 不检查配置文件权限（loader.go:11-17）——cp 出的 0644 sbc.yaml 含明文密码即全局可读。CWE-732。

### 领域八已排除的可疑点（要点）
1. nft exec 注入——不可利用（同领域七结论，ip.String() 无 zone 可控）。2. go:embed 面——干净。3. unsafe/cgo——全仓库为零。4. reflect 用途单一（仅 ${ENV} 展开）。5. Resolver.cache 无界——不可达（键仅来自配置）。6. 硬编码秘密——零（含 git 全历史）。7. 出向 TLS 默认校验开启（关键正面结论）。8. SRV 重解析递归——不存在。9. fsnotify 误重载 tmp——不可达（basename 过滤）。

## 领域一发现（子代理返回 + 主代理复核与冲突裁决）

> 证据：sipgo v1.4.3 + pion/sdp v3.0.19 源码（GitHub 官方 tag tarball，存 /tmp/freesbc-audit/）。主代理裁决记录：① D6-5 vs D1-3 冲突——亲自读 parser_stream.go:117-121（Write 无条件累积）+ :125-139（MaxMessageLength 仅完整解析后检查）+ transport_tcp.go:227-240（ErrParseSipPartial → return 继续读）→ **D1-3 正确，TCP 每连接内存无界**；② D1-5 解析器语义亲自核实（parser.go:341-365：行按首个 \r 切割，裸 \n 残留在头值中，\r 不可能残留）✔。

### [D1-1 + D5-6/X3 合并，升级 High] 无认证 INVITE → 媒体端口池耗尽 + 真实运营商外呼（DoS + 话费欺诈）
- 严重度：**High**（领域一与领域五独立分析收敛，主代理采信领域一的升级理由）/ 置信度：High / 类型：已确认漏洞 / CWE-770、CWE-799
- 位置：sig/b2bua.go:80-87（identify 后无任何鉴权）、:276-285（每 INVITE 先占 2 对端口=4 socket）、:553-592,801-964（failover 全链 × ring 60s 拉长占用）、shield/shield.go:74-76（peer 源 IP 完全豁免限速）、media/portpool.go:54-84（耗尽→503）、config/schema.go:127-129,162-163（默认池 ≈4096 并发呼叫）
- 前置：任一已配置 peer 的源 IP（恶意/被攻陷运营商，或 UDP 伪造——见 D1-2）。
- 可利用场景：① 单 peer ~70 INVITE/s（单目标、60s 占用）占满全部并发会话 → 合法呼叫 503；② 每个攻击 INVITE 触发对真实运营商的呼出（digest 自动重试）→ **toll fraud**；③ 路由 from==to 时自环放大直至端口耗尽；④ **盲伪造**（无需看到响应）：A-leg ACK 永不到达时 aLeg.Respond 在 64×T1≈32s 后失败，但 B-leg 已 Ack 为真实接通的计费通话（b2bua.go:1065-1077 顺序：先 Ack B-leg，Respond 失败才 BYE）；⑤ RTP 静默 5m 才回收 + D5-4 垃圾包续期进一步拉长占用。
- 修复：per-peer INVITE 速率/并发呼叫上限；全局半呼上限（503+Retry-After）；register 型 peer 要求 digest；媒体端口分配推迟或限时共享；半呼数监控告警。回归：单 peer 高速 INVITE 洪水下断言其他 peer 呼叫不受影响；伪造源 INVITE 断言 ACK 超时后 B-leg 必被 BYE。

### [D1-2] peer 识别仅凭源 IP：UDP 下伪造源 IP = 完整 peer 信任（系统性信任边界缺陷）
- 严重度：High（信任模型缺陷；利用需伪造能力或恶意 peer）/ 置信度：High（代码路径确定；可利用性取决于网络位置 uRPF/BCP38）/ 类型：配置风险 / CWE-345、CWE-348
- 位置：sig/identify.go:17-30（唯一凭据=allowed_ips 匹配源地址）；sig/server.go:360-401,488-582（所有 handler 唯一鉴权即此）
- 链：伪造源 IP=peer IP 的任意 SIP 请求 → peer 豁免 → identify 命中 → 取得该 peer 全部权限（D1-1 全部后果 + 收响应）。TCP/TLS 不受影响（三次握手）。
- 修复：文档化信任边界并建议公网仅启用 tcp/tls 监听；register 型/敏感路由要求 digest（IP+凭据双因子）；运营商侧 uRPF；高价值操作可绑定 From 校验。回归：伪造源 INVITE 在启用 digest 的 peer 上被 401。

### [D1-3 + D6-5 合并，升级 High] SIP TCP/TLS：无连接上限 + 无读/空闲超时 + 流式解析缓冲无界累积
- 严重度：**High** / 置信度：High / 类型：已确认漏洞（依赖上游，FreeSBC 零缓解） / CWE-400、CWE-779
- 位置：sig/server.go:324-358（裸 net.Listen/tls.Listen 无包装；sipgo 有 WithTransportLayerReadFilter 钩子未用）；sipgo transport_tcp.go:62-72（accept 无上限）、:151-168（读循环无 SetReadDeadline/Idle）、parser_stream.go:117-121（Write 无条件追加）、:125-139（MaxMessageLength 仅完整解析后检查）、transport_tcp.go:227-240（ErrParseSipPartial 被忽略继续读）
- Source→sink：打开连接 → 慢喂无 CRLF 字节 → parseSingle 持续 ErrUnexpectedEOF → partial 被忽略 → **缓冲跨读无界增长（1:1 内存）**；或 M 条静默连接各占 goroutine+fd 永不回收 → fd/goroutine 耗尽连带 UDP 与媒体端口。
- 修复：FreeSBC 侧立即可行——包装 listener（最大连接数+每连接空闲超时+握手超时）；上游 ParserStream 加累积上限。回归：半开连接慢喂 1MB 断言内存有界或被断；N>上限连接断言拒绝。

### [D1-4 + D5-5 合并] 拓扑隐藏缺口：relay 的 audio m= 段透传 a=candidate / a=fingerprint / a=ice-* / o= 会话标识 / s=
- 严重度：Medium / 置信度：High / 类型：已确认漏洞 / CWE-200
- 位置：sig/sdp.go:63-87（rewriteSDP）、:163-201（rewriteSDPCrypto relay 段保留除 crypto/rtcp 外全部属性——:176-190）、:59-61,159-161（o= 只改地址，username/sess-id/version 原样）；对比 declined 段被清空（:198-200）——sdp.go:144-148 注释自证已知 candidate 泄露问题但只修了被拒段。
- 影响：运营商侧观测呼叫方内网拓扑（WebRTC 化 PBX 的 host candidate 内网 IP:port、DTLS 指纹、ICE 凭据），反向同理——正是 SBC 拓扑隐藏承诺要阻断的；同时 ICE-enabled 端点会尝试向内网地址连媒体（互操作故障）。
- 修复：relay 段属性白名单（rtpmap/fmtp/ptime/sendrecv/...），剔除 candidate/fingerprint/ice-*/setup/extmap；o= username/sess-id 重写为 SBC 生成值。回归：含 a=candidate/fingerprint 的 offer 断言 B-leg offer 不含。

### [D1-5] 裸 LF 头注入：A-leg 身份字段与被叫号码未经清洗进入 B-leg，序列化不转义
- 严重度：Medium / 置信度：High（注入路径经 sipgo 源码核实；远端危害取决于对端解析器） / 类型：已确认漏洞 / CWE-93
- 位置：sig/b2bua.go:1089-1103（buildFrom：DisplayName/User 原样透传）、:752-753（outNumber → Request-URI user）、sig/routing.go:44-50（无 match 时被叫号码原样透传）；sipgo headers.go:605-621（FromHeader 原样输出含引号内任意字符）、uri.go:72-79（Uri 原样输出 User）、parser.go:341-365（**裸 \n 残留在头值/URI/DisplayName 中；\r 不可能残留**——主代理已亲自核实）
- 链：A-leg `From: "x\n<伪头>: y" <sip:a@h>` → 解析保留 \n → buildFrom → B-leg 序列化原样写入 → 对把裸 LF 当行终止的宽松 SIP 栈（现实中常见）= **向运营商注入任意后续行**（头注入/请求走私）；display name 内嵌 `"` 破坏引号配对。CR/CRLF 注入已排除（见排除清单 1），严格栈不受影响。
- 修复：buildFrom/Request-URI user 过滤 \r \n，display name 另剔 `"` `<` `>`（或 quoted-pair 转义）；被叫号码字符白名单。回归：From/user/URI user 含 \n 与 " 的 INVITE 断言 B-leg 不含原样字节或被 400。

### [D1-8] 除 onInvite 外全部 SIP handler 与 sipgo 分发 goroutine 无 panic 恢复
- 严重度：Medium-Low / 置信度：High（无 recover 已核实；onBye/onAck 具体 panic 点未发现） / 类型：纵深防御建议 / CWE-248
- 位置：sipgo transaction_layer.go:140（handleRequestBackground 无 recover）、server.go:258-269；FreeSBC 仅三处 recover（b2bua.go:81、relay.go:106、admin/server.go:118）；onOptions/onAck/onBye/onNoRoute（sig/server.go:488-582）裸奔——任一 panic = **进程整体退出**（Go 语义）。
- 佐证（真实 panic 已存在，当前恰被 onInvite 的 recover 吞掉）：INVITE 缺 To 头 → b2bua.go:127 `req.To().Params` nil 解引用；缺 From 头 → :1090 `req.From()` 后 nil 解引用（sipgo makeServerTxKey 带 magic-cookie branch 不要求 From，transaction.go:312-315；ReadInvite 只查 Contact/CSeq）。当前后果是可靠性的（呼叫静默丢弃无 400），但同类 nil-deref 若出现在 onBye/onAck 调用的 sipgo dialog 代码中即进程死亡。
- 修复：withShield 统一 defer recover+500；onInvite 前置显式校验 From/To/Call-ID 存在并回 400。回归：缺 To/From 的 INVITE 断言 400；onBye 注入 panic 断言进程存活。

### 领域一其余条目（已并入其他领域，交叉引用）
- [D1-6]（伪造源 ban 注入/nft 风暴）→ 并入 [D7-1]/[D7-2]（结论一致）。
- [D1-7]（事务层 400/CANCEL-200/auto-100 旁路静默承诺）→ 并入 [D6-4]，补充：CANCEL 命中 INVITE 事务直接回 200（transaction_layer.go:155-184）、INVITE 建事务 200ms 后自动 100 Trying（transaction_server_tx.go:41-71）。
- [D1-9]（Call-ID 碰撞）→ 并入 [D6-9]。
- [D1-10]（refresh re-INVITE 无 tag 校验）→ 并入 [D5-2/X1]。**注意**：该子代理持更保守评估（认为第三者难获 compare SDP、200 无副作用）；主代理维持 Medium 评级——理由：SDP 高度可预测（o= 被剥离）+ peer 无限速豁免使 200-vs-501 oracle 可全速爆破 + answer 含 SRTP master key 是真实敏感输出。
- [D1-11]（TLS 恒自签）→ 并入最终报告的 TLS 配置风险项（与主代理链 X2、领域八的出向校验结论合并）。
- [D1-12]（UDP 池无界 + 单读循环单核瓶颈）→ 并入 [D6-1]（两子代理对同一代码独立得出相同机制；严重度取 D6-1 的 High）。

### 领域一已排除的高价值可疑点（均经 sipgo/pion 源码核实）
1. **CR/CRLF 头注入——不可行**（仅裸 LF 可行，已列 D1-5）：nextLine 按行内首个 \r 切割且要求 \r\n 成对，头值/URI/DisplayName/Call-ID 内不可能残留 \r；头折叠以单空格连接。
2. **Content-Length 走私——不可行**：流式与数据报均「最后出现的 CL 生效」；FreeSBC 所有出站消息经 SetBody 重算 CL 整体重序列化，从不回传攻击者原始字节。
3. **伪造超大 CL 大分配——不可行**：make 前有 totalRead+CL>65535 预检（parser_stream.go:190-198）；UDP 读缓冲 32768。
4. **跨呼叫 BYE/ACK/CANCEL 劫持（第三方）——不可行**：dialog 键=Call-ID+双 tag；A-leg To-tag=sipgo uuid v4（crypto 随机，dialog_ua.go:35-45）、B-leg From-tag=12B crypto/rand（b2bua.go:1127-1137）；CANCEL 需 16 随机字符 branch。猜测空间 ≥2^96。
5. **头级拓扑泄露——不存在**：B-leg INVITE 头全部为 SBC/sipgo 新构造（From/Contact/Supported/SE/Min-SE + 全新 Via/Call-ID/CSeq/To）；A-leg 的 Via/From host/Call-ID/P-Asserted-Identity/Remote-Party-ID/History-Info/Record-Route/Route **零复制**。SDP 属性级泄露除外（D1-4）。
6. **整数溢出（CSeq/Max-Forwards/时长头）——不可行**（ParseUint 32 位+上限检查；headerSeconds Atoi 失败即 0）。
7. **UDP 反射放大——≈1:1 非有效放大器**（响应≈请求大小；响应目的 IP 固定为包源 IP，不能指向任意第三方）。
8. **pion/sdp v3.0.19 崩溃/指数放大——低风险**（逐行状态机、与体长线性、上游自带 fuzz harness）。

## 阶段 D — 不可信输入数据流追踪（source → validation → sink 汇总）

以下每条链标注「校验缺在哪一行」。✅=有校验，⚠️=校验存在但有缺口，❌=无校验。

| # | Source | Validation | Sink | 缺口 |
|---|--------|-----------|------|------|
| F1 | UDP/TCP/TLS SIP 字节 | sipgo 解析器：数据报 65535 上限 ✅；**TCP 流式累积无界 ❌**（parser_stream.go:117-121，D1-3） | 解析→事务→handler | TCP 每连接内存无界；解析在 shield 之前（成本不受保护，D7-5） |
| F2 | 传输层源地址 | net.SplitHostPort+ParseAddr ✅；**无 Unmap ❌**（sig/server.go:391-401，D7-4） | identify（allowed_ips 匹配）→ peer 信任；shield 豁免；banList/nft 键 | 双栈监听下 fail-closed（无绕过）但内核 ban 错表；identify 仅 IP 无二次凭据（D1-2） |
| F3 | From 头 DisplayName/User | ❌ 无任何清洗（b2bua.go:1089-1103 buildFrom 原样透传） | B-leg From 头序列化 | 裸 LF/引号注入对端（D1-5）；缺 From 头 → nil deref panic（D1-8） |
| F4 | Request-URI user（被叫号码） | 路由正则匹配 ✅（有 match 时）；**无 match 时原样透传 ❌**（routing.go:44-50）；无字符白名单 ❌ | transformNumber → B-leg Request-URI user | LF 注入面（D1-5）；ReDoS 不适用（RE2） |
| F5 | Call-ID 头 | ❌ 无长度/字符校验（b2bua.go:1350-1355） | registry/killers/sdps 三 map 键（攻击者可控主键）；/api/calls JSON；WebUI textContent 渲染 | 键碰撞跨呼叫干扰（D6-9）；XSS 已排除（领域三排除项 1）；无长度上限（D3-5） |
| F6 | User-Agent 头 | isScanner 子串匹配 ✅（11 指纹） | **ban 决策 → nft exec + 内核规则**（shield.go:81-86→nftables.go:75-85） | 判定在限速前 ❌（D7-1）；ban 对象=声称的源 IP ❌ 无真实性验证（D7-2） |
| F7 | INVITE body（SDP） | pion/sdp 解析+audio 检查 ✅；remoteMediaIP 拒绝主机名 ✅（netip.ParseAddr，无 DNS 解析） | SetExpectedRemote/latch arm；rewriteSDPCrypto 重写 | a=candidate 等属性透传泄露（D1-4）；B-leg 应答 c= 无源 IP cross-check（可接受——经事务匹配） |
| F8 | a=crypto 行 | parseCryptoAttrs 严格校验 ✅（suite 白名单/base64/30B/MKI 截断，crypto.go:45-83） | NewSRTPContext | 无缺口；但防重放未启用（D5-1，sink 侧库配置） |
| F9 | RTP/RTCP 包 | latch.accept：strict IP 匹配+post-latch IP:port ✅；SSRC/PT/seq ❌（设计接受，D5-3） | 明文纯转发（不解析）✅；SRTP pion unprotect ✅ fail-closed | lastRx 在认证前刷新（D5-4） |
| F10 | Admin HTTP 请求 | Basic Auth（bcrypt+恒时）✅；缺 Authorization 头也执行 bcrypt ⚠️（server.go:102-105，D3-3） | /api/*（含 PUT 配置写回：1MiB 限额+Parse 校验+原子写 ✅）、DELETE kick、/metrics | 无失败限速（D3-3）；无 Cache-Control（D3-1）；响应头缺失（D3-2） |
| F11 | PUT 配置 body | 1MiB 上限 ✅、If-Match ✅（可选）、config.Parse 严格校验 ✅（strict YAML+ENV+validate） | writeFileAtomic 原子写回 ✅ | 权限位继承（D4-3）；TOCTOU（D4-4）；别名炸弹（D4-2，goccy 层） |
| F12 | 配置文件（本地） | Load→Parse→validate ✅ strict；**无文件大小上限 ❌**（loader.go:11-17，D4-7） | Store 原子发布 ✅ | 权限不检查（D8-7）；fsnotify 静默死亡（D4-8） |
| F13 | DNS 应答 | SRV/A 结果直转端点 ⚠️（无 Target "."/port 0 过滤，D8-2；无地址类别告警，D8-3） | 出站 INVITE/REGISTER 目标 | 无 DNSSEC/pinning（D8-3）；解析无 ctx 超时（D8-1） |
| F14 | 杂散 SIP response / 畸形请求 | ❌ 不经 shield/identify（事务层直接处理） | 每包 goroutine+Info 日志；400 响应；全字节 Error 日志（D6-4） | 日志洪泛 + 打破静默承诺 + 1:1 反射 |
| F15 | 环境变量（${ENV} 展开） | 严格语法、缺失整份拒绝 ✅（expand.go） | 内存 Config；日志/错误/API 均已核实不回显展开值 ✅ | 仅内存驻留（进程内可读，随 D8-6 root 面放大） |

**结论**：配置面（F10-F12、F15）与密码学材料处理（F8、SDES 生命周期）的数据流纪律最好；**信令面 F1-F6 的校验前移不足**（解析/识别/封禁决策都发生在不受保护的层），媒体面 F7/F9 基本符合设计但有两处库级缺口（D5-1 防重放、D5-4 认证前计时）。

### Fuzz target 建议（仓库当前为零 fuzz 覆盖；只给建议，未向仓库添加文件）

| 目标 | 建议签名 | 种子语料 | 动机 |
|------|----------|----------|------|
| SIP 解析边界 | `func FuzzSipgoParser(f *testing.F)`（喂 sipgo sip.ParseFSM/stream 两种） | RFC 3261 示例消息、缺头/坏 CL/裸 LF/超长头/畸形 URI 变异 | D1-3/D1-5/D1-8 的解析层缺口；上游 sipgo 无公开 fuzz harness |
| SDP 重写 | `func FuzzRewriteSDP(f *testing.F)`（sig 包，输入 []byte → rewriteSDP/rewriteSDPCrypto 断言不 panic 且输出可再解析） | pion/sdp 测试语料 + a=candidate/fingerprint/多 m= 段/畸形 c= | D1-4 属性透传与重写路径 |
| a=crypto 解析 | `func FuzzParseCryptoAttrs(f *testing.F)`（sig 包，断言不 panic、长度恒 30B 或丢弃） | RFC 4568 示例 + 坏 base64/MKI/超长/空 suite | SDES 密钥处理健壮性 |
| 配置解析 | `func FuzzConfigParse(f *testing.F)`（config 包，输入 YAML → Parse 断言 error 或成功，绝不 panic/卡死） | sbc.example.yaml + 锚点/别名炸弹/深嵌套/重复键/巨大标量 | D4-2 的 goccy 别名展开缺口（fuzz 可同时捕获栈溢出） |
| ${ENV} 展开 | `func FuzzExpand(f *testing.F)`（config 包） | `${A}`、`${`、`$}`、嵌套、空名、超长 | expand.go 反射遍历 |
| RTP latch 决策 | `func FuzzLatchAccept(f *testing.F)`（media 包，输入源地址字节+期望地址） | v4/v6/4in6/zone/非法串 | D7-4 规范化缺口回归 |
| 限速器 | `func FuzzParseRateLimit(f *testing.F)` | "20/s per_ip" 变异、空串、巨数 | ParseRateLimit 边界 |

## 领域二发现（子代理返回 + 主代理复核）

> 主代理最终验证：D2-3 的唯一未决环节已闭环——sig/server.go:166-169（NewUA 无 TLS 选项）→ sipgo ua.go:14（tlsConfig 零值 nil）、:100 → transport_layer.go:130-132（nil → &tlsEmptyConf 零值配置）→ **出向 TLS 对端证书校验确认开启（系统 CA、ServerName=主机名、默认 TLS1.2+）**。全链经本地 sipgo 源码核实 ✔。主代理模型更正确认：出向摘要客户端是 sipgo 自带（DoDigestAuth/WaitAnswer），icholy/digest 仅测试用。

### [D2-1 + D1-2 合并] SIP 身份=源 IP、无质询：UDP 下伪造 peer IP 即完整 peer 信任（盗打+限速豁免）
- 严重度：High（信任模型缺陷；利用需伪造能力或恶意 peer）/ 置信度：High / 类型：配置风险 / CWE-290、CWE-345
- 证据：sig/server.go:363-369（identify 只信 req.Source()，已对 sipgo transport_udp.go 源核实 SetSource 来自 socket 对端与 Via 无关）；shield/shield.go:72-94（peer 豁免）；sig/b2bua.go:83-87,186,297（identify 通过即路由出局）。
- 影响：①盗打（B-leg 由 SBC 自行 ACK，盲伪造即可产生最长 5m 的真实计费通话）；②伪造源 OPTIONS 反射 ≈1:1（弱）；③伪造流量无速率上界。TCP/TLS 不受影响（需完成握手）。
- 修复：公网入向走 tcp/tls；可选 per-peer digest 质询或 mTLS（与 TLS 配置项联动）；shield 对 peer 保留高限额而非全免；文档要求 uRPF。

### [D2-2] allowed_ips 校验无宽度/非空/规范性约束
- 严重度：Medium / 置信度：High（宽度/非空已核实；非规范前缀待验证）/ 类型：配置风险 / CWE-129、CWE-284
- 位置：config/validate.go:98-106（逐条 parse，无非空/宽度/规范性检查）、:257-266（parsePrefixOrAddr 不 Masked()）。
- 链：`allowed_ips:[0.0.0.0/0]` → 校验不拒 → IdentifyPeer 对任意 IPv4 源返回该 peer → 叠加 D1-2 = 任意公网源盗打。空 allowed_ips → AllowsIP 恒 false（fail-closed 但属 footgun）。`203.0.113.7/24`（本意单主机）按 /24 生效（netip 语义）。
- 修复：拒绝/警告过宽前缀（IPv4 /16、IPv6 /48 量级）；要求非空；非规范前缀报错或存 Masked()。回归：TestValidateRejectsWildcardPrefix 等。

### [D2-3 + D1-11 + X2 合并] TLS 凭据配置面缺失：入向恒自签（SDES 对主动 MITM 无保护）+ 出向无信任锚可配
- 严重度：Medium（启用 srtp 且信令非受验证 TLS 时实际影响为 High）/ 置信度：High / 类型：配置风险·纵深防御 / CWE-295、CWE-319
- 位置：sig/tlscert.go:16-53（每进程新自签证书，注释自认无证书配置）；sig/server.go:334-345；sig/b2bua.go:259-267,688-697（仅非 TLS 时 Warn——**transport=tls 时零告警**，自签提供虚假安心感）；出向已核实校验开启但无 per-peer CA/客户端证书配置。
- 要点：a) 入向自签 → 对端无法验证 SBC → 主动 MITM 双侧终结 TLS 即可读取/替换 a=crypto → 实时解密「SRTP」媒体；b) 出向校验开启但无法配信任锚 → 自签/私有 CA 运营商不可达（握手失败→503）→ 被迫退回 udp/tcp → SDES 密钥与 digest 凭据明文，同时封死用 mTLS 缓解 D2-1 的路；c) MinVersion 未显式设置（Go 1.25 默认已禁 1.0/1.1，当前不可利用，建议显式）。
- 修复：增加 tls_cert/tls_key/client_ca（入向）与 peers.tls_ca/tls_client_cert（出向）；自签+tls 传输也告警；显式 VersionTLS12。回归：TestOutboundTLSRejectsSelfSignedPeer。

### [D2-4 + D3-3 + D6-7 合并] Admin 面三重叠加：明文 HTTP Basic + 无失败限速 + 无条件 bcrypt
- 严重度：Medium（admin.listen 暴露于不可信网络时为 High）/ 置信度：High / 类型：已确认漏洞（暴露时）/ CWE-319、CWE-307、CWE-770
- 完整链：明文 Basic 嗅探 → `GET /api/config/raw` 逐字节返回全部配置（**所有 peer 明文 SIP 密码**/${ENV} 引用/admin hash）→ `PUT /api/config` 改 allowed_ips/路由 → 与 D1-2/D2-2 组成完整盗打链。CPU-DoS：无 Authorization 头也跑满 bcrypt（admin/server.go:102-105）；在线爆破无锁定。validate.go:167-170 允许 0.0.0.0:8080 静默通过。
- 修复：非 loopback+无 TLS 启动 Fatal/显著 Warn；admin TLS/unix socket；缺 Authorization 头直接 401 跳过 KDF；每 IP 失败限速接入 shield；补全超时。

### [D2-5] 出向 digest：质询参数全由远端控制，捕获 Authorization 可离线字典攻击
- 严重度：Medium / 置信度：Medium-High / 类型：配置风险·纵深防御 / CWE-522、CWE-319
- 位置：sig/register.go:96-105（REGISTER 单次 DoDigestAuth）；sig/b2bua.go:819-823（INVITE 凭据经 WaitAnswer）。realm/nonce/algorithm/qop 全取自对端 401/407；非 TLS（默认 udp）下被动捕获者可对 RFC2617 响应值做离线字典攻击（MD5）；无 qop 时同 method+URI 的 REGISTER 在 nonce 有效期内可重放。凭据 ${ENV} 展开后明文常驻内存。
- 修复：per-peer auth.realm 钉扎、口令强度文档、信令走 TLS。

### [D2-6 → 并入 D6-9]（Call-ID 键控三表覆盖语义——与 D6-9/D1-9 同一发现，领域二补充：DELETE 路由认证已验证、踢任意呼叫属管理员 by-design）

### [D2-7] 出向目标由配置+DNS 决定（SSRF-by-config，Low，无未授权可达路径，记录备查——接 D2-5/D8-3 的 DNS 投毒链）

### 领域二已排除的可疑点（要点）
1. IPv4-mapped IPv6 绕过 AllowsIP——不成立且 fail-closed（sipgo raddr.String() 将 4-in-6 规范化为点分十进制 → ParseAddr 得 Is4；与两种前缀族均不匹配 → drop）。
2. Via received/rport 参与识别——不可达（identify 只读 req.Source()；received/rport 全仓库无读取）。
3. Admin 路由认证缺口（尾斜杠/%2F/方法错配）——逐一核对全部落 requireAuth 或同样认证的 catch-all；测试覆盖。
4. Basic Auth 用户名枚举——实现正确（恒时比较+bcrypt 无条件双验证）。
5. 出向 InsecureSkipVerify——0 命中且出向链路已全源码核实校验开启。
6. PUT 写回 ${ENV} 展开态——不会（verbatim）。7. handleUI 路径遍历——不可达（embed 固定文件名）。8. CSRF 触发 PUT——预检阻断（低置信推理，未浏览器验证）。9. /healthz——19 字节固定 JSON。

## 5. 纵深防御建议（与漏洞分开；已在上文各领域节标注「纵深防御」的汇总）

1. **SIP 入口前置过滤**（同时缓解 F-01/F-03/F-04/F-10）：用 sipgo `WithTransportLayerReadFilter`（transport_layer.go:72-77，当前未用）或 nftables 非白名单源早期 DROP，把「非 peer 源的一切字节」挡在解析/事务/日志之前。
2. 全部 SIP handler 统一 panic recover（withShield 包装层）+ 缺失必备头的显式 400（D1-8）。
3. 响应头基线：nosniff、X-Frame-Options: DENY、Referrer-Policy、最小 CSP；敏感路由 no-store（F-18 修复时一并）。
4. Admin：Host/Origin 校验（DNS rebinding 纵深）、连接上限、缓存凭据外的会话机制评估。
5. 密码学：显式 MinVersion=TLS1.2；per-peer digest realm 钉扎；SRTP 会话可选 a=ssrc 预学习（D5-3）；RTCP CNAME 剥离/重写（D5-7）。
6. 运维/部署：systemd 最小权限样例（CAP_NET_BIND_SERVICE+CAP_NET_ADMIN、NoNewPrivileges、ProtectSystem、DynamicUser，D8-6）；配置 0600 检查告警（D8-7/D4-3）；peer 域名防过期文档（F-21）。
7. 供应链：最小 CI（vet、test -race、govulncheck、go.sum 冻结检查）；发布 -trimpath+SBOM+签名（D8-5）。
8. 可观测性：nft backend 激活状态、ban 表水位、每 peer 并发/INVITE 速率、半呼数——全部纳入 metrics 告警。

## 6. 已运行命令及实际结果

见前文「阶段 E — 验证命令及实际结果」（go build/vet/test/-race/govulncheck/gosec 全部 `command not found` exit 127——本机无 Go 工具链，如实记录跳过；fuzz 覆盖检查：零 fuzz target）。

## 7. 覆盖范围

- **代码**：全仓库 72 个 .go 文件（17,320 行，其中生产文件 36 + 测试 36）全部纳入八个领域的审查范围；非仅最近 diff。分布：main.go 1；admin 13（生产 6）；callstate 2（生产 1）；config 13（生产 7）；media 9（生产 4）；shield 10（生产 5）；sig 24（生产 12）。另有 admin/webui/index.html（embed，522 行逐行审）。
- **外部入口**：阶段 B 清单 E1–E9（SIP UDP/TCP/TLS、RTP 端口池、Admin HTTP、配置文件+fsnotify、nftables exec、出站 DNS、出站 SIP/REGISTER）全部审查。
- **第三方**：sipgo v1.4.3（传输/事务/解析/dialog/客户端各关键文件逐行，本地副本）、pion/sdp v3.0.19（结构级）、pion/srtp v3.0.12（CreateContext 默认行为+上游核对）、goccy/go-yaml v1.19.2（option/decode/parser/format 四个关键文件，上游核对）、icholy/digest（确认仅测试导入）、go.sum 全量文本审阅。
- **数据流**：阶段 D 的 F1–F15 十五类不可信输入 source→validation→sink 全部走查。
- **已排除的高价值攻击链**（负结果同样重要）：存储型/反射型 XSS（textContent 纪律完整）、CSRF/CORS、CRLF/CR 头注入（仅裸 LF）、Content-Length 走私、跨呼叫 BYE/ACK/CANCEL 劫持（tag 熵 ≥2^96）、头级拓扑泄露（零头复制）、${ENV} 展开值落盘/入日志/入 API、nft argv 注入、Prometheus 标签注入、redaction 缺口、IPv4-mapped IPv6 识别绕过（fail-closed）、admin 路由认证缺口（逐一核对）、ReDoS（RE2）、YAML 重复键/未知键静默（strict 拒绝）、媒体资源回收泄漏（全部错误路径核实）、DNS SRV 重解析递归。

## 8. 未覆盖内容与证据缺口（含全部歧义记录）

1. **无 Go 工具链**（最重要缺口）：build/vet/test/-race/govulncheck/gosec 全部未运行；所有并发正确性与 CVE 结论为源码级静态判断。`go test ./... -race` 与 govulncheck 是恢复工具链后的第一优先动作。
2. **运行时未验证的语义**：netip 4in6 行为（D7-4 的验证程序已写好待跑：/tmp/freesbc-audit/netip-check/）、nft CLI 对 timeout "0s" 与 v4 包 ip6 saddr 的行为（禁跑约束）、goccy 别名炸弹实际表现（D4-2）、bcrypt 实测耗时（文献估计 60-130ms）、浏览器 CSRF/预检行为（推理排除）。
3. **sipgo 未逐行部分**：事务 FSM 全表（畸形/乱序输入下的 panic/死锁未穷举）、ua.go→transport 之外的 TLS 边缘（已核链路足够支撑结论）。
4. **部署面未知**（按最不利假设评估）：目标机是否有 nft 二进制与权限（决定 F-03/F-04 激活）；是否以 root 运行；admin 是否按示例绑 loopback；上游是否有 uRPF（决定 F-07 实际可利用性）；是否多租户（决定 F-08 评级）。
5. **歧义处理记录**：①「shield 解析前限速？」——实现为 handler 层，按事实记录并列为 F-10/D7-5 缺口；② 设计文档「re-INVITE 授权 Relatch」与实现（一律 501）不一致——按更保守的实现评估，文档准确性问题已记录；③ 领域一/领域五对 F-06 前置（伪造源可达性）与领域一/领域二对 F-08 可利用性存在评估分歧——主代理裁决并给出理由（见各发现）；④ 子代理从 GitHub 官方 tag 下载了 sipgo/pion-sdp 源码用于离线核对（只读取证，未发送任何攻击流量；领域二报告其网络在审查中途退化，此后改用本地副本）。
5b. **正面确认但依赖外部源码的结论**（已在正文标注）：pion/srtp 默认 no-replay、sipgo 出向 TLS 零值校验、goccy 别名展开无界——三者均有本地/上游源码行级证据，但非本仓库代码。

## 9. 整改计划

### 立即（公网部署阻断项，发布前完成）
1. F-01/F-10：readFilter 前置过滤或等价（非 peer 源字节在解析前丢弃）。
2. F-02：TCP/TLS listener 包装——最大连接数、空闲/读超时、流式累积上限。
3. F-03/F-05：scanner 判定移到限速后 + ban 写路径全局限幅/串行队列 + ban 表硬上限。
4. F-04：UDP 单包判定仅内存 ban；nft 规则限定 SIP 端口/协议；admin unban；nftables 默认 off。
5. F-06：per-peer 并发呼叫与 INVITE 速率上限；B-leg 拨号前对 A-leg 做防伪造校验（如 ACK 确认或 digest）。
6. F-07 缓解（部署策略）：公网仅 tcp/tls 或上游白名单+uRPF；文档明示 UDP+IP-auth 的伪造边界。
7. F-14 缓解（部署策略）：admin 仅 loopback；非 loopback+无 TLS 启动强告警。

### 7 天内
8. F-08：refresh 分支 dialog ID（Call-ID+双 tag）校验，不符 481。
9. F-09：SRTPReplayProtection(64)/SRTCPReplayProtection(128)（同步调整 pumpTransform 测试泵）。
10. F-05 补充：nft set maxsize；F-03 补充：exec.CommandContext。
11. F-16：allowed_ips 宽度/非空校验；F-17：sourceAddr 统一 Unmap。
12. F-18：敏感路由 no-store；F-14 补充：缺 Authorization 头跳过 bcrypt+失败限速；F-15：admin 凭据热生效或变更拒绝。
13. F-12：身份字段字符清洗/白名单；F-11：SDP 属性白名单。

### 30 天内
14. F-13：TLS 证书/信任锚/mTLS 配置面。
15. F-19：peer 宽松限速+per-peer INVITE 上限；F-20：digest realm 钉扎与文档。
16. F-21：出向 TLS pinning 选项；DNS 地址类别告警；singleflight+超时（D8-1）。
17. 全部 Low/纵深项（§5 清单）；panic recover 全覆盖（D1-8）；netip/nft 行为的运行时验证与回归测试。
18. 建立 CI（vet/test -race/govulncheck/go.sum 冻结）与 §10 的 fuzz target；恢复 Go 环境后补跑本报告 §6 全部命令。

## 10. 最优先回归测试与 fuzz target 清单

**回归测试（按修复优先级）**：
1. TestUDPPoolBoundedUnderUniqueSourceFlood（F-01；RSS 曲线断言）
2. TestTCPConnLimitAndIdleTimeout / TestTCPStreamAccumulationCap（F-02；慢喂 1MB 无 CRLF 断言断开或内存有界）
3. TestScannerBanRateLimited / TestNFTExecBounded（F-03；注入 run 记录器并发 ban 1000 IP 断言上限）
4. TestBanListCap（F-05；假时钟注入超上限 IP 断言表被钳制）
5. TestUDPScannerSinglePacketInMemoryBanOnly（F-04；断言不触 nft）+ TestAdminUnban
6. TestPeerInviteRateLimit / TestBlindSpoofInviteBYEsBlegOnAckTimeout（F-06）
7. TestRefreshReInviteWrongTagGets481（F-08；错 tag/错源断言不回 answer）
8. TestSRTPReplayDropped（F-09；同包重放两次断言第二次 drop）
9. TestRequireAuthSkipsKDFOnMissingHeader / TestAdminAuthFailureRateLimit（F-14）
10. TestAdminAuthHotReloadRevokesOldPassword（F-15）
11. TestValidateRejectsWildcardPrefix / TestSourceAddrUnmaps4in6（F-16/F-17）
12. TestBuildFromStripsLFAndQuotes / TestBInviteHasNoCandidateAttrs（F-12/F-11）
13. TestConfigNoStoreHeaders（F-18）；TestMissingToFromInviteGets400（D1-8）

**Fuzz target**：见前文「Fuzz target 建议」表（SIP 解析、SDP 重写、a=crypto、配置解析、${ENV} 展开、latch 决策、限速器七个目标，含签名与种子语料）。

## 附：/tmp/freesbc-audit/ 产出文件清单

| 文件/目录 | 内容 |
|-----------|------|
| main-agent-notes.md | 主代理交叉分析笔记（链 X1-X3、主验证记录） |
| domain-1-notes.md … domain-8-notes.md | 八个领域的子代理完整报告（含全部排除项与理由） |
| sipgo-1.4.3/（+sipgo-1.4.3.tar.gz、sipgo-src/、sipgo.tgz） | sipgo v1.4.3 官方 tag 源码副本（领域六/一取证用，行号引用凭据） |
| sdp-src/（+sdp-3.0.19.tar.gz） | pion/sdp v3.0.19 源码副本（领域一取证用） |
| netip-check/ | D7-4 netip 语义验证程序（写好待 Go 环境运行） |
| sipgo-transport.go | 领域二早期取证片段 |
| fixes/（README + 草稿 01–03） | 修复补丁草稿（会话后段按误解放向产出：F-01/F-10 readFilter、F-02 TCP 限流、F-03/F-05 shield 节流与上限；**未编译未评审的参考稿**，不属于本次审计交付物） |

（仓库内唯一新增文件为本报告 SECURITY-AUDIT-20260826.md；未修改任何生产代码。）

> 注：阶段 A/B/E 过程记录、领域一至八详证与阶段 D 数据流表构成 §4（按子代理完成顺序嵌入，非按编号排序）；D 系列编号即 §3 汇总表的合并来源，逐条可查。
