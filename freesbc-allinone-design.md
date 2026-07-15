# FreeSBC — All-in-One 开源 SBC 设计文档

背景：借鉴 LibreSBC，解决其部署复杂、入门门槛高的核心痛点。

## 1. 背景与动机

### LibreSBC 架构分析

| 组件 | 技术 | 职责 |
|------|------|------|
| FreeSWITCH | C | 信令 B2BUA + 媒体处理（RTP、转码） |
| callng | Lua（嵌入 FreeSWITCH） | 呼叫路由逻辑、CDR 事件、安全事件 |
| liberator | Python (FastAPI) | 管理 API、配置生成（Jinja2→XML）、CDR、nftables 管理 |
| Redis | — | 配置/状态存储 |
| webui | 静态 JS | 管理界面 |
| ansible + docker | — | 部署编排 |

**优点**：继承 FreeSWITCH 的电信级互操作性与转码能力；控制面/媒体面分层清晰；安全能力完整（nftables shield、topology hiding）；MIT 协议。

**缺点（本项目要解决的）**：部署组件多（FreeSWITCH + Redis + Python + Lua + nftables + ansible），任一环节版本不匹配即故障；四种语言维护成本高；配置链路长（API → Redis → Jinja2 → XML → reload），排错跨 4 层；无单二进制交付；FreeSWITCH 本身安装门槛高。

### 产品命题

对标 Caddy 的体验：**下载一个二进制、一个配置文件、`./FreeSBC run` 即可运行的开源 SBC**。

## 2. 范围决策（已确认）

- **媒体深度**：仅 RTP 中继 + SRTP 加解密，**不做转码**。转码留给后端软交换。覆盖 topology hiding、媒体安全、NAT 穿越等主流 SBC 场景。SRTP 密钥协商**仅支持 SDES**（SDP `a=crypto`，信令走 TLS）；DTLS-SRTP 随 WebRTC 范围一并排除。
- **定位**：中小企业/ITSP 单节点优先，单机数百~数千并发。HA 用主备/VRRP 后置。
- **MVP 包含**：SIP trunk 对接（含**出向 trunk 注册**：向运营商发 REGISTER + digest 认证，覆盖注册型 trunk）、路由引擎、topology hiding（B2BUA + SDP 重写）、RTP 中继 + SRTP(SDES)、内置安全防护、内嵌 WebUI。
- **MVP 不含**（后续版本）：注册代理/Registrar（即**服务**话机/终端注册——与上述出向注册是两回事）、CDR、转码、集群。
- **配置模型**：声明式 YAML 配置文件为唯一真相源，支持热重载；WebUI/API 是配置文件的编辑器。

### 技术路线选型

- **方案 A（选定）：纯 Go 从零构建** — sipgo（SIP 栈）+ pion（SRTP/SDP）+ go:embed WebUI。真正单二进制、零依赖、交叉编译。代价：SIP 互操作性需自行踩坑（以 MVP 聚焦 trunk 对接收敛风险——对端为运营商/PBX，行为比话机规范）。
- 方案 B（否决）：Go 控制面 + 内嵌 FreeSWITCH 单容器。互操作性免费但非真单体，FreeSWITCH 复杂度只是被隐藏，产品差异化弱。
- 方案 C（否决）：Go 信令 + rtpengine。性能最强但需内核模块，部署门槛与目标矛盾。

## 3. 整体架构

单进程四平面：

```
┌─────────────────────────────────────────────────┐
│                   FreeSBC (单进程)                  │
│  ┌───────────┐   ┌────────────────────────────┐ │
│  │ 管理平面    │   │ 信令平面 (sipgo)             │ │
│  │ HTTP API  │──▶│ SIP B2BUA                  │ │
│  │ WebUI     │   │ UDP/TCP/TLS :5060/:5061    │ │
│  │ (embed)   │   └──────────┬─────────────────┘ │
│  └───────────┘              │                   │
│  ┌───────────┐   ┌──────────▼─────────────────┐ │
│  │ 安全平面    │   │ 媒体平面                     │ │
│  │ 限速/封禁   │──▶│ RTP Relay + SRTP (pion)    │ │
│  │ 扫描识别    │   │ UDP 端口池 16384-32768      │ │
│  └───────────┘   └────────────────────────────┘ │
│  配置真相源: sbc.yaml (fsnotify 热重载)            │
│  运行时状态: 纯内存 (呼叫状态表)                     │
└─────────────────────────────────────────────────┘
```

### 关键设计决定

1. **B2BUA 而非 proxy**：入呼/出呼各一条 leg，SDP 完全重写指向自身媒体端口，实现 topology hiding 与媒体安全。sipgo 提供事务/对话层，B2BUA 逻辑自研（参考 diago）。
2. **运行时状态纯内存**：单节点定位下呼叫状态不落盘，进程重启丢在途呼叫（与 Kamailio 默认一致）。配置文件是唯一持久化。
3. **配置热重载语义**：变更 → 校验 → 原子替换（`atomic.Pointer[Config]`）→ 新呼叫用新配置，在途呼叫不受影响。校验失败保持旧配置，进程永不因坏配置崩溃。
4. **安全平面应用层实现**：每 IP 限速、扫描器 UA 指纹、失败阈值自动封禁，内存封禁表，可选联动 nftables（`auto/on/off`），nftables 非硬依赖（与 libresbc 相反）。
5. **媒体面安全（latching 加固）**：首包 latching 仅在媒体流建立前生效，默认要求首包源 IP 与 SDP 信令 IP 一致（每 peer 可配 `strict/loose` 应对强 NAT），媒体建立后**不再重新 latch**，防 RTP 劫持。

### 信令互操作基线（MVP 必备）

对接真实运营商/PBX 的最低要求，全部纳入 MVP：

- **应答入站 OPTIONS**：运营商用 OPTIONS 做 trunk 健康检查，不应答会被判死。
- **Session Timers（RFC 4028）**：支持 `Session-Expires`/`Min-SE` 协商与定时刷新，许多运营商强制要求。
- **100rel/PRACK 透传**：两 leg 间正确透传可靠临时响应（运营商 183 早期媒体场景）。
- **Digest 认证客户端**：应答出向 INVITE/REGISTER 的 401/407 挑战（peer 配置的 `auth` 凭据）。
- **出向 REGISTER**：peer 配 `register: true` 时向运营商周期注册（到期前刷新、失败退避重试），注册失败该 peer 标记不可用并计入 metrics。
- **DNS SRV**：peer 地址支持 SRV 解析，priority/weight 结果并入 failover 列表；无 SRV 记录回退 A/AAAA。

## 4. 模块划分

```
FreeSBC/
├── main.go                  # 入口：flag 解析、启动编排
├── config/
│   ├── schema.go            # YAML 结构体 + 校验规则
│   └── reload.go            # fsnotify 监听、原子热重载
├── sig/                     # 信令平面
│   ├── server.go            # sipgo 装配 (UDP/TCP/TLS)、入站 OPTIONS 应答
│   ├── b2bua.go             # leg 配对、状态机、re-INVITE/BYE 转发、PRACK 透传、session timers
│   ├── routing.go           # 路由匹配 → 选网关 → failover（含 DNS SRV 解析）
│   ├── auth.go              # digest 认证客户端（401/407，INVITE/REGISTER 共用）
│   ├── register.go          # 出向 trunk 注册状态机（定时刷新、失败退避）
│   ├── sdp.go               # SDP 解析/重写
│   └── normalize.go         # 号码变换（正则替换）
├── media/
│   ├── portpool.go          # RTP 端口池分配/回收
│   ├── relay.go             # UDP 转发引擎（每呼叫 goroutine 对）
│   └── srtp.go              # SRTP↔RTP (pion/srtp)
├── shield/
│   ├── ratelimit.go         # 每 IP 令牌桶
│   ├── scanner.go           # 扫描器 UA 指纹库
│   ├── banlist.go           # 内存封禁表 + 可选 nftables 联动
│   └── acl.go               # IP 白/黑名单
├── admin/
│   ├── api.go               # REST API (net/http 无框架)
│   ├── webui/               # 前端静态文件 (go:embed)
│   └── metrics.go           # Prometheus /metrics
└── callstate/               # 内存呼叫状态表（API 查询/踢呼叫）
```

### 模块间接口

1. **sig → media**：`media.Allocate(ctx) (Session, error)` — INVITE 时申请媒体会话（两对端口），地址写入重写 SDP；结束 `Session.Close()` 回收。media 不懂 SIP，sig 不碰媒体包。
2. **sig → shield**：sipgo middleware 挂 `shield.Check(srcIP, msg) Verdict` — 每个入站请求先过安全平面，返回拒绝/静默丢弃/放行。
3. **全部模块 → config**：只读 `config.Current()` 取快照（atomic 解引用无锁），单呼叫内用同一快照，保证配置一致性。

### 依赖清单

`emiago/sipgo`（SIP 栈）、`pion/srtp` + `pion/rtp`（SRTP）、`pion/sdp`（SDP）、`fsnotify`（热重载）、`goccy/go-yaml`（配置，保留注释）、`prometheus/client_golang`（指标）。无数据库、无 Redis、无 Web 框架。

## 5. 配置文件形态与路由模型

设计目标：新手照 20 行示例跑通第一通呼叫。libresbc 的五层引用模型（interconnection / media class / capacity class / translation class / routing table）压扁为三个顶层概念：**listen / peers / routes**。

```yaml
listen:
  sip:
    - udp://0.0.0.0:5060
    - tls://0.0.0.0:5061          # 证书不配则自签
  media:
    port_range: 16384-32768
    public_ip: auto                # auto = STUN 探测，或写死

peers:
  carrier-a:
    address: sip.carrier-a.com:5060  # 支持 DNS SRV，无记录回退 A/AAAA
    transport: udp
    auth: { username: acct01, password: "${CARRIER_A_PASS}" }
    register: true                 # 注册型 trunk：周期 REGISTER + digest 认证
    allowed_ips: [203.0.113.0/24]  # 入呼按源 IP 识别 peer
  internal-pbx:
    address: 10.0.0.10:5060
    allowed_ips: [10.0.0.0/8]

routes:
  - name: outbound
    from: internal-pbx
    match: { to: "^9(\\d+)$" }
    transform: { to: "$1" }
    to: [carrier-a]                # 顺序即 failover 顺序
  - name: inbound
    from: carrier-a
    to: [internal-pbx]

shield:                            # 有合理默认值，整段可省略
  rate_limit: 20/s per_ip
  auto_ban: { failures: 5, window: 60s, duration: 1h }
  nftables: auto

admin:
  listen: 127.0.0.1:8080
  auth: { username: admin, password_hash: "..." }
```

### 路由语义

- **入呼识别**：源 IP 匹配 peer 的 `allowed_ips` → 确定 `from`；无匹配交给 shield（默认静默丢弃）。
- **匹配**：按 `routes` 顺序，`from` + `match` 正则首条命中即用，无优先级数字。
- **failover**：`to` 列表依序尝试，5xx/超时切下一个；peer 带被动健康检查（连续失败冷却）+ 可选 OPTIONS 探测。
- **变换**：`transform` 支持正则捕获组，内联于路由，无需单独定义再引用。
- **codec 过滤**：按 peer 配置过滤 SDP codec 列表（纯 SDP 层操作，不涉及转码）。

### WebUI 与配置文件

WebUI 读写同一份 YAML（`GET/PUT /api/config`：校验 → 写文件 → 热重载）。手工改文件与 WebUI 双向可见。**配置回写策略**：WebUI 编辑以结构化 PATCH 作用于 YAML AST（goccy/go-yaml `ast` 包），只改动目标节点，不整体重序列化，以保留注释与排版；`${ENV_VAR}` 引用原样存取，**永不**把展开后的明文写回磁盘。

## 6. 呼叫数据流

```
1. INVITE 到达 (carrier-a → :5060)
2. shield.Check(srcIP)          → 限速/封禁/ACL，不过则静默丢弃
3. peer 识别                     → 源 IP ∈ carrier-a.allowed_ips
4. config.Current()             → 取配置快照，绑定本呼叫
5. routing.Match(from, to号码)   → 命中路由 → 目标 peer
6. media.Allocate()             → 分配两对 RTP/RTCP 端口（A/B 侧）
7. SDP 重写                      → A leg 应答 SDP 指向本机 A 侧端口
8. 新建 B leg INVITE，SDP 指向本机 B 侧端口
9. B leg 应答 → 状态机桥接（180/183/200 映射回 A leg）
10. 双向媒体经 relay 转发；首包 latching：以对端首个 RTP 包实际源地址为准（NAT 穿越，加固规则见 §3 关键设计决定 5）
11. 任一侧 BYE → 转发另一侧 → Session.Close() 回收端口 → 状态表清除
```

re-INVITE（hold/恢复/改 codec）透传并同步重写 SDP。relay 对 payload 不感知。

## 7. 错误处理

| 场景 | 行为 |
|------|------|
| 坏配置（启动时） | 报错退出，指出行号与原因 |
| 坏配置（热重载） | 保持旧配置运行，日志 + metrics 报警标志 |
| B leg 全部 failover 失败 | A leg 返回最后错误码（或可配置统一码） |
| 媒体端口耗尽 | INVITE 拒 503，metrics 计数 |
| 单呼叫内部 panic | per-call goroutine recover，杀该呼叫并释放资源，进程不死 |
| 半死呼叫（BYE 丢失） | RTP 静默超时（默认 5 分钟）自动拆线 |
| 出向 REGISTER 失败 | 指数退避重试，该 peer 标记不可用（路由跳过），metrics 报警 |

## 8. 测试策略

- **单元测试**：routing 匹配/变换、SDP 重写、shield 判定（多为纯函数）。
- **SIP 集成测试**：sipgo 在测试内模拟 UAC/UAS，真实 UDP 回环，覆盖建立/failover/re-INVITE/BYE 全状态机。
- **互操作验收**：sipp 场景脚本 + docker-compose 里的真实 FreeSWITCH/Asterisk 对端，CI 运行。
- **媒体验证**：relay 双向收发 + SRTP 端到端包级断言。
- **性能基准**：**Linux 上**单机 1000 并发呼叫 RTP 转发 CPU < 50%（`SO_REUSEPORT` + `sendmmsg`/`recvmmsg` batch syscall，Linux 专属优化），作为回归门槛。darwin/windows 构建走普通收发路径，功能完整但不做性能承诺。

## 9. 非目标（明确排除）

- 音频转码（G.729/AMR/opus 互转）
- 注册代理/Registrar——服务话机注册（MVP 后评估；出向 trunk 注册**在** MVP 内）
- DTLS-SRTP 密钥协商（MVP 仅 SDES）
- CDR（MVP 后评估）
- 分布式集群/无缝 failover
- K8s Operator
- 视频/WebRTC 网关
