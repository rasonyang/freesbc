# FreeSBC 安全专项代码审查报告（审计后增量）

- 审查日期：2026-08-31
- 审查基线：`b998f0883c363f4890f950f576d9de99d52c5630`（`docs/SECURITY-AUDIT-20260826.md` 的审查 HEAD）
- 审查对象：`b998f08..HEAD`（3 个 commit）全部变更 + 审计 High 发现的现 HEAD 复验
- 审查 HEAD：`7fe89d9`（fix(sig): honor ring_timeout against silent targets）
- 审查方式：diff 逐行审查 + sipgo v1.4.3 上游源码（module cache 本地副本）行级核对新代码所依赖的 `WaitAnswer`/`inviteCancel` 行为 + Go 1.27.0 实跑 build/vet/test（审计报告 §6/§8 所列的最大证据缺口——「无 Go 工具链」——本次已闭合）
- 授权：仓库所有者授权本次审查。只读审查 + 本地测试验证（含临时 git worktree 基线条测试），未修改任何生产代码。

> 结构：§1 变更概览；§2 ring_timeout 修复（7fe89d9）专项审查——本次审查重点；§3 webui 变更（7c99323）；§4 interop 测试资产（13a5d93）；§5 审计发现现 HEAD 复验；§6 总体结论与 P0 分级。审计原文的编号体系（F-01…F-21、D 系列、T-01…T-37）沿用不变。

---

## 1. 变更概览

| commit | 内容 | 安全面初审 |
|---|---|---|
| `7fe89d9` fix(sig): honor ring_timeout | `dialTarget` 中 `WaitAnswer` 与 per-attempt deadline 竞争，250ms grace 后 abandon 尝试，孤儿 goroutine 兜底晚到 2xx 的 ACK+BYE 拆除 | **重点审查对象**（§2） |
| `7c99323` fix(admin): Config tab 自动加载 | webui 首次打开 Config 页自动 fetch `/api/config/raw`（防重入守卫） | 干净（§3） |
| `13a5d93` test(interop) | SIPp+FreeSWITCH 真实场景套件 + `test/interop/sbc.yaml` + sipp 场景 XML + RTP pcap | 干净（§4） |

## 2. ring_timeout 修复（7fe89d9）专项审查

### 2.1 修复内容与动机

sipgo v1.4.3 的 `WaitAnswer` 在目标**从未发任何响应**时进入 `inviteCancel`，而 `inviteCancel` 按 RFC 3261 §9.1（无 provisional 不得发 CANCEL）会阻塞到 INVITE 事务死于 Timer_B（~32s）——黑洞目标因此把每次拨号尝试钉住 ~32s，`ring_timeout`/failover 完全失效（interop 报告 F1）。

修复方式（`sig/b2bua.go:818-919`）：把 `WaitAnswer` 放进派生 goroutine，与 `attemptCtx`（per-attempt ring 预算）竞争；deadline 先到时给 250ms grace 窗口等 `waited` 交付，仍无交付则置 `abandoned`、`cancel()` 并按 failRing 分类返回；晚到 2xx 由孤儿 goroutine 用 `ackThenBye` 拆除。实测（interop T4b）黑洞 carrier-a 的 failover 从 32.004s 降至 4.256s。

### 2.2 新发现

#### [S-01] 孤儿 goroutine 逃逸 recoverCall 保护：panic 即进程整体死亡 — Medium
- 位置：sig/b2bua.go:848-866（`go func(bLeg, attemptCtx) { WaitAnswer...; ackThenBye... }`）
- 事实：修复前 `WaitAnswer`/`relay`（relayProvisional→processAnswerSDP→aLeg.Respond）/teardown 全部 inline 运行在 onInvite goroutine 内，受 `recoverCall`（b2bua.go:1437，审计 D1-8 唯一防线）保护——panic 只丢一路呼叫。修复后这些代码跑在每次 dial 尝试派生的**无 recover 的孤儿 goroutine**：任一处 panic（含并发竞争诱导的 nil-deref，见 S-02）= 进程退出（Go 语义），连带全部在途呼叫与媒体面。sipgo 的 `inviteCancel`/`Do(CANCEL)`/`WriteAck` 路径此前从未在 FreeSBC 侧 goroutine 中裸奔过。
- 修复：goroutine 内 `defer recover()`（Error 日志 + 正常退出）；回归测试用注入 panic 断言进程存活。

#### [S-02] 250ms grace 为启发式：超时后双 goroutine 并发触碰对话与媒体状态 — Low-Medium
- 位置：sig/b2bua.go:888-918（grace select）；:849-853（OnResponse→relay）
- 机制 1（grace 超时竞态）：若孤儿 goroutine 的 `relay` 在 grace 内未跑完——A-leg TCP 写阻塞（F-02：SIP TCP 连接无写超时）或响应恰在 deadline 前到达且 SDP/SRTP 处理慢——主路径 abandon 后照常 dial 下一目标并 `aLeg.Respond`，与孤儿 relay **并发调用同一 `DialogServerSession.Respond`**。已核实 sipgo dialog_server.go:264-283 `WriteResponse` 无任何锁（直接写 `s.Dialog.InviteResponse`）→ 对话状态数据竞争，可进一步诱导 panic（喂给 S-01）。`media.Session` 侧（SetSRTP 原子指针、Relatch 带锁）单独看是安全的，但语义上的覆盖（后到先赢）不受保护。
- 机制 2（select 随机性）：sipgo dialog_client.go:246-261 `WaitAnswer` 主循环 `select` 在 `tx.Responses()` 与 `ctx.Done()` 同时就绪时随机选择——deadline 后仍可能取响应分支并 relay 数轮（响应洪泛下被拉长）。
- 一行修复（同时堵死两条入口）：
  ```go
  OnResponse: func(res *sip.Response) error {
      if abandoned.Load() { return nil }   // 主路径已放弃本尝试
      responded.Store(true)
      return relay(res)
  }
  ```
- 回归：迟到 18x 注入断言不触发 aLeg.Respond；grace 窗口边缘并发断言 -race 干净。

#### [S-03] 静默目标的活事务由串行变并行（F-06/F-19 放大器）— Low
- 位置：sig/b2bua.go:862-866、897-918（abandon 路径）
- 机制：每个被 abandon 的静默目标留下一个到 Timer_B（~32s）才消亡的活 INVITE 事务 + goroutine（修复前为 1 个串行阻塞的 onInvite goroutine）→ K 个静默目标 = 每 INVITE 并发 K 个事务/goroutine。同时媒体端口占用时长从 32s 升为 `ring_timeout`（**默认 60s**，config/schema.go:162-163）——审计 F-06 按 60s 估算的占用时长对静默目标现在才真正成立。
- 影响：伪造 peer 源 IP 的 INVITE 洪泛下（F-07 全免限速），事务层内存/goroutine 数 ×K。
- 结论：**T-06（per-peer 并发配额）/T-18（peer 宽松限速）的优先级上升**——它们本来就在审计第一/二梯队，本条是增量理由。

#### [S-04] ackThenBye 的 Ack 无超时：孤儿 goroutine 可永久滞留 — Low
- 位置：sig/b2bua.go:1412-1423（ackThenBye）；:863、:995（传入 `context.Background()`）
- 机制：BYE 有 `byeContext` 5s 上限（:384-386），但 `bLeg.Ack(ctx)` 用调用方 ctx——孤儿路径与 raced-2xx 主路径传的都是 `context.Background()`。B-leg TCP 黑洞后 Ack 写阻塞（出向连接同样无写超时）→ goroutine 永久泄漏。
- 修复：Ack 同样用 5s 级 `byeContext`。

#### [S-05] 100 Trying 即置 responded：只回 100 即沉默的目标不进冷却 — Info
- 位置：sig/b2bua.go:850-852（`responded.Store(true)` 对一切响应触发）
- 影响：`penalize: !responded.Load()`（:909）使只发过 100 Trying 即沉默的目标不冷却，端点健康机制噪音。非安全项，记录备查。

### 2.3 已排除的疑点（sipgo 源码核实）

1. **迟到 18x 媒体劫持——不可达**。曾怀疑孤儿 goroutine 在 abandon 后 ~32s 窗口内 relay 迟到 18x：`processAnswerSDP` 会 `SetSRTP(SideB, 攻击者上下文)` + `Relatch(SideB, 攻击者地址)`，恶意 carrier（已配置 peer）可借此把已接通呼叫的媒体偷换成自己的音频（与 F-08 同级的话务注入）。核实 sipgo dialog_client.go:251-257、349-401：ctx.Done 后 `WaitAnswer` 直接进入 `inviteCancel`，**`OnResponse` 在 inviteCancel 内从不被调用**（`InviteResponse==nil` 时仅等首个响应以决定 CANCEL；有 provisional 时 loop_487 只等 487/64×T1，期间的响应不再回调）。残余暴露面仅 §S-02 的 select 随机性（milliseconds 级）。
2. 双 ackThenBye——不可达（teardown 只在 abandon 路径与 main 路径二选一：`abandoned.Load()` 门 + main 路径无条件拆除互斥）。
3. `waited` 缓冲 channel 使孤儿 goroutine 的 send 永不阻塞，主路径提前返回不构成泄漏。
4. 孤儿 goroutine 生命周期有界：≤~64s（Timer_B + CANCEL 事务 Timer_F + loop_487 64×T1），属 §S-03 的并发放大而非泄漏。
5. `bLeg`/`attemptCtx` 以参数而非闭包捕获传入（:848），规避了 return 槽位共享的数据竞争（commit 注释已自证，-race 验证通过）。

### 2.4 测试实况（审计证据缺口闭合后的首次全量执行）

| 命令 | 结果 |
|---|---|
| `go build ./...` | ✅ 通过（go1.27.0，`~/go-toolchain`） |
| `go vet ./...` | ✅ 无告警 |
| `go test ./...` | admin/callstate/config/media/shield 全绿；**sig 包 flaky**（详见下） |
| `go test ./sig/ -race` | 一次通过（本次运行 flake 未复现） |

- **flaky 为基线同病，非本次引入**：baseline `b998f08`（临时 worktree）三次运行同样失败——`TestBridgeAnswersSessionTimerRefresh` / `TestBridgeBrokenAnswerSDPGets502` / `TestBridgeSRTPRequiredBNoCryptoFailsOver` / `TestBridgeDigestAuth`，失败签名 ~3.16-3.26s（测试内 3s 超时），每次失败的测试集合不同；HEAD 上同样出现。commit message 所称 "full suite passes with -race" 在本机不可复现（环境差异）。每轮 ~82 条 `WARN UDP ref went negative on try close`（sipgo 连接池 refcount 噪音）同样基线同病。
- 新测试覆盖：failover 成功（2s 内断言）+ caller-cancel 分类；**未覆盖**：raced-2xx teardown、grace 窗口边缘、abandon 后晚到响应——S-01/S-02 修复时应补这三个回归。

## 3. webui 变更（7c99323）：干净

- 新代码只经 `textContent`/`.value` 赋值（`configText.value = text`），无 innerHTML/eval 等新 sink；fetch 为 GET + `credentials: same-origin`，落在既有 Basic Auth 边界内；`configLoading` 防重入守卫正确（`.then` 尾链无条件复位）。
- 唯一提示：打开 Config tab 即自动渲染含明文凭据的配置原文（暴露边界与既有 Load 按钮相同，非新漏洞）——但使 **F-18（T-16 Cache-Control: no-store）** 的浏览器磁盘缓存问题更实际。

## 4. interop 测试资产（13a5d93）：干净

- `test/interop/sbc.yaml` 的 `password_hash` 经 bcrypt 实测匹配 **testpass123**（测试口令，非生产凭据）；`g711a.pcap` 为 SIPp 上游样本（strings 扫描无 Authorization/password 等敏感字段）；sipp 场景 XML 无敏感信息。
- 文件头正确提示 5070 与 sig 包集成测试端口冲突（先停实例再跑套件），无安全隐患。

## 5. 审计发现现 HEAD 复验

- **变更面**：`git diff b998f08..HEAD --name-only` 仅 `admin/webui/index.html` + `sig/b2bua.go`（+测试/文档/interop 资产）——其余 70 个 .go 文件自审计后零改动，审计全部行号结论原样成立。
- **High 逐条复验（本次亲自 grep/Read）**：
  - F-03：shield/shield.go:81-86 scanner ban 仍先于 :87-92 限速 ✔
  - F-04：shield/nftables.go:62-63 `ip saddr @banned4 drop` 仍无 dport/协议限定；无 unban 路由 ✔
  - F-06：sig/b2bua.go:276-285 每 INVITE 仍分配 2 对端口、无准入控制 ✔
  - F-07：sig/identify.go:17-30 仍仅源 IP 匹配（AllowedIPs 字典序首个命中）✔
  - F-14：admin/server.go:102-105 无条件 bcrypt（含无 Authorization 头）、:80 仅 ReadHeaderTimeout ✔
  - F-01/F-02/F-05 位于未变更文件（sig/server.go、shield/banlist.go）✔
- **T-01..T-37 无一实现**：无 `sig/readfilter.go`、`sig/listenerlimit.go` 等任何整改文件；shield/config/media/admin 生产代码零改动。
- **行号漂移说明**：b2bua.go dialTarget 区 +96（如 buildFrom 1089→1185、relayProvisional 1272 起）；审计引用的早段行号（:127 refresh re-INVITE、:276 端口分配、:80 onInvite）不变。
- **F-06 参数更新**：静默目标占用时长 32s → `ring_timeout`（默认 60s）——见 §S-03。

## 6. 总体结论与 P0 分级

1. **审计结论在现 HEAD 完全成立**：公网部署阻断项（F-01…F-06）与信任模型缺陷（F-07）均未开始整改；`b998f08..HEAD` 的三个 commit 均非安全修复（一个呼叫可靠性修复、一个测试套件、一个 UI 体验）。
2. ring_timeout 修复本身可靠——排除了媒体劫持链，failover 语义正确——但引入 S-01…S-05 需跟进，其中 S-02 一行短路 + S-01 recover + S-04 Ack 超时建议随第一/二梯队批次合入。

### P0（公网部署阻断项，发布前必须完成）

| 级别 | 项 | 对应任务 | 理由 |
|---|---|---|---|
| P0 | F-01/F-10 入口前置过滤 | T-01 | 未认证源字节先于一切防护进入解析/连接池/日志（OOM、日志洪泛） |
| P0 | F-02 TCP/TLS 连接上限+空闲/读超时 | T-05 | 未认证 Slowloris 稳定 OOM/fd 耗尽 |
| P0 | F-03 scanner ban 在限速前 + nft 风暴 | T-04 | 未认证 fork/exec 风暴（CPU/PID/内存） |
| P0 | F-05 banList 无上限 | T-03 | 未认证唯一源洪水数 GB 内存 |
| P0 | F-04 伪造源内核黑洞 + 全协议规则 | T-02 | 1 包/小时黑洞任意第三方 IP（含自身 DNS）且无解除 |
| P0 | F-06 无认证 INVITE 端口池耗尽+真实外呼 | T-06 | 未认证话费欺诈 + 合法呼叫 503 |
| P0（部署闸门） | F-07 缓解：公网仅 tcp/tls 或上游 ACL+uRPF | 运维项（代码修复挂起中） | UDP 下源 IP 伪造=完整 peer 信任（盗打） |
| P0（部署闸门） | F-14 缓解：admin 仅 loopback | 运维项（T-09/T-26 落前） | 明文 Basic+全部 SIP 凭据一个端口暴露 |

> P0 定义沿审计 §2「阻止公网部署」标准：未认证攻击者即可稳定实现的服务中断/资源耗尽，或未认证话费欺诈。F-07/F-14 的代码级修复（digest 质询、admin TLS）属新产品能力，短期以部署闸门方式封堵，故列 P0（部署闸门）而非 P0（代码）。

### P1（紧随其后，7 天内批次）

- F-08（T-07）：refresh re-INVITE 无 dialog 校验——已配置 peer 可探测他腿 SDES master key
- F-09（T-08）：SRTP 防重放（RFC 3711 MUST 违约）
- F-19（T-18）：peer 全免限速 + TerminateGracefully 钉住——S-03 使其更紧迫
- F-14 代码面（T-09）：缺头跳过 KDF + 失败限速
- F-15（T-15）：admin 凭据热生效（口令吊销缺口）
- **本次新增**：S-01（orphan recover）、S-02（abandoned 短路）、S-04（Ack 超时）——建议与 T-06/T-18 同批合入

### P2（其余按 REMEDIATION-PLAN 第三/四梯队）

F-10 残余（T-12）、F-11（T-14）、F-12（T-13）、F-13（T-17）、F-16..F-21、全部 Low/纵深项（T-20…T-37），以及 S-05（记录备查）。

---

> 附：本次审查新增/更新的产物：本文档；记忆更新（测试套件 flaky 为基线同病、Go 工具链可用）。未修改任何生产代码；临时基线 worktree 已删除。
