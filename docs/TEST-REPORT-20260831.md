# FreeSBC 真实场景集成测试报告(SIPp + FreeSWITCH)

**测试日期**:2026-08-31 · **被测对象**:FreeSBC(仓库 HEAD `b998f08`,版本 `dev`)
**测试人**:Claude Code 自动化测试 · **测试性质**:真实端到端互通验证

## 1. 执行摘要

用 SIPp 模拟 PSTN carrier-a(/carrier-b),用本机 FreeSWITCH 模拟 internal-pbx,对 FreeSBC 做了
12 个场景的端到端测试,覆盖:基本出/入局呼叫、振铃超时、故障转移、486 透传、无路由 404、
RTP 静默超时拆除、admin 踢话、OPTIONS/盾牌自动封禁、30 路并发压测、通话中配置热重载。

**结果:11 通过 / 0 失败 / 1 跳过(SRTP,环境限制),发现 2 个值得修复的问题(F1、F2)。**

| 结论项 | 结果 |
|---|---|
| 基本呼叫(SIP B2BUA + RTP 中继) | ✅ 双向媒体四向全通,号码变换/CLI 透传/SDP 改写全部正确 |
| ring_timeout 故障转移 | ✅ 目标振铃不接时 4s 精确 CANCEL 并转移(4.001s) |
| **黑洞目标(零响应)故障转移** | ⚠️ **延迟约 32s(Timer_B),ring_timeout 不生效 → 问题 F1** |
| 呼叫拆除(BYE/CANCEL/超时/踢话) | ✅ 全部干净收敛,资源(端口/注册表)归零 |
| 并发(30 路 @ 5cps) | ✅ 30/30 成功,峰值 29 路并发/58 端口,无泄漏 |
| 可观测性(admin API/metrics/日志) | ✅ /api/calls 生命周期正确,指标与呼叫状态严格一致 |
| 配置热重载 | ✅ 通话中重载不中断现有呼叫 |
| SRTP(SDES)互通 | ⏭️ 跳过:FreeSWITCH 构建不含 libsrtp(见 §10) |

## 2. 环境与拓扑

单机部署(192.168.31.5,Ubuntu 24.04,WiFi wlp3s0):

```
 SIPp (carrier-a)  127.0.0.2:5090 ─┐
 SIPp (carrier-b)  127.0.0.2:5092 ─┼─lo──▶ FreeSBC 0.0.0.0:5070 ──lan──▶ FreeSWITCH 192.168.31.5:5060
                                   │      媒体池 16384-32768                  (internal-pbx, internal profile)
 SIPp (UAC 模拟主叫) 127.0.0.2 ────┘      public_ip=192.168.31.5              dialplan: 9196=echo, 9197=milliwatt
```

- **peer 识别纯靠源 IP**(`sig/identify.go`):FreeSWITCH 从 192.168.31.5 发出 → internal-pbx;
  SIPp 绑定 loopback 别名 **127.0.0.2**(`ip addr add 127.0.0.2/8 dev lo`)→ carrier-a/carrier-b。
- **FreeSWITCH 零改动接入**:入局走 internal profile(5060),`apply-inbound-acl=domains` 对
  192.168.31.0/24 免鉴权;出局用 `originate sofia/external/sip:9XXX@192.168.31.5:5070 …`。
- **版本**:FreeSBC `dev`(HEAD b998f08)· FreeSWITCH 1.11.2-release(2026-08-16 构建)
  · SIPp c496186-TLS-PCAP(源码构建)· Go 1.27.0。
- 测试资产:`test/interop/sbc.yaml`(测试配置)、`test/interop/sipp/*.xml`(场景)、
  `test/interop/sipp/g711a.pcap`(RTP 样本,源自 SIPp 源码)。原始证据:/tmp/freesbc-test/(pcap、SIPp trace、API 快照)。

## 3. 测试配置要点(test/interop/sbc.yaml)

| 参数 | 值 | 说明 |
|---|---|---|
| `listen.sip` | `udp://0.0.0.0:5070` | 5060 被 FreeSWITCH 占用 |
| `listen.media.public_ip` | `192.168.31.5` | **必须为真实地址**(`auto` 未实现,占位符会导致媒体不通) |
| `rtp_timeout` | 20s | T7 用 |
| `ring_timeout` | 4s | T3/T4 加速 |
| `carrier-a/b` | 127.0.0.2:5090/5092,`allowed_ips [127.0.0.2/32]` | |
| `internal-pbx` | 192.168.31.5:5060,`allowed_ips [192.168.31.5/32]` | |
| routes | outbound: `^9(\d+)$`→`$1` → [carrier-a, carrier-b];inbound: carrier-a → internal-pbx | |
| shield | `rate_limit 200/s`,`auto_ban 10/60s/1h`,`nftables off` | |
| admin | 192.168.31.5:8080(admin/testpass123) | |

## 4. 场景明细

### T1 出局基本呼叫 ✅ PASS

- **步骤**:SIPp UAS(carrier-a,5090,`-rtp_echo`+pcap 播放)→ FS
  `originate … sofia/external/sip:92001@192.168.31.5:5070 9197 XML default` → 通话 7s → `hupall`。
- **断言与证据**:
  - B-leg INVITE:`sip:2001@127.0.0.2:5090`(**9 已剥**);From `"PBX-1000" <sip:1000@192.168.31.5:5070>`
    (**CLI 透传**);Contact `sip:192.168.31.5:5070`(无 user);带 Session-Expires/Min-SE(t1_uas_msg.log)
  - SDP 改写:B-leg INVITE `c=IN IP4 192.168.31.5`、`m=audio 16390`(池端口)、codec 列表透传、
    `m=video 0` 拒收(非 audio 段正确声明)
  - 呼叫中 `/api/calls`=1(from=internal-pbx→carrier-a)、`freesbc_active_calls 1`、`media_ports_in_use 2`;
    挂断后全部归零(t1_calls_mid/end.json)
  - RTP 四向全通(lo pcap):FS 腿 597/362 双向、SIPp 腿 362/362 双向
  - FS 通道 PCMU/8000,milliwatt 音流;SIPp 1 successful / 0 failed

### T2 入局基本呼叫 ✅ PASS(附观察)

- **步骤**:SIPp UAC(127.0.0.2)INVITE `9197` → SBC → FS milliwatt 应答 → 6s 后 SIPp BYE。
- **断言与证据**:200 的 SDP 已改写为 `c=192.168.31.5`、`m=audio 16400`(池端口);
  FS 收 INVITE 号码=9197(public→default dialplan 命中 milliwatt);`/api/calls` 轮询显示完整
  生命周期(注册 15.1s → 拆除 21.4s,from=carrier-a→internal-pbx);RTP 双向(FS 腿 500/300,
  SIPp 腿 300/300);SIPp 1 successful。
- **观察**:SIPp 的自定义场景在含 `<exec>` 动作时**不自动发 ACK**,SBC 按 T1 间隔重传 200
  直至收到 ACK/BYE,呼叫不受影响 —— SBC 对缺失 ACK 的容忍行为正确(robustness,正面记录)。

### T3 振铃超时 ✅ PASS

- **步骤**:两个 ring-forever UAS 占满 5090/5092,FS 拨 92001。
- **证据**:carrier-a:INVITE→180→**CANCEL 在 4.002s**;failover 至 carrier-b(2ms 内)再 4.005s 后
  CANCEL;SBC 日志两条 `b-leg not answered: context deadline exceeded`(4s/8s);FS 通道在第二个
  CANCEL 后立即销毁(收 408)。`/api/calls` 全程无记录(未应答不注册,符合设计)。

### T4 故障转移 ✅ PASS + 问题 F1

- **T4a(目标振铃不接)✅**:carrier-a ring-forever + carrier-b 应答。carrier-a 在 **4.001s**
  被 CANCEL,carrier-b 即时接续,`/api/calls` 显示 `to=carrier-b`,RTP 双向全通,通话正常建立拆除。
- **T4b(目标黑洞)⚠️ 问题 F1 → 已修复并复验**:5090 无监听 + carrier-b 应答。**修复前**主叫
  (SIPp 冒充 internal-pbx)INVITE 后 **32.004s** 才收到 200(预期 ~4s);**修复后实测
  4.256s**(4s ring_timeout + 250ms 收尾宽限 + 6ms),carrier-b 在 deadline 后 2ms 收到 INVITE。
  三方证据互证:
  - 修复前 SBC 日志:`b-leg not answered err="transaction terminated … Timer_B timed out" target=carrier-a`(03:30:35.062);
    修复后:`b-leg not answered err="context deadline exceeded" target=carrier-a`(04:13:01.624)
  - 修复前 carrier-b 的 INVITE 在 03:30:35.062 才到达(黑洞腿死于 Timer_B 后才转移);
    修复后在 deadline 后 2ms 到达(04:13:01.625)
  - **根因**(读代码确认):sipgo v1.4.3 `dialog_client.go:355-366` `inviteCancel()`——目标零响应时
    `s.InviteResponse == nil`,阻塞等任意响应或 `tx.Done()`(Timer_B=32s),**不发送 CANCEL 也不返回**;
    FreeSBC 的 ring 预算注释明确假设超时必 CANCEL,与实际行为矛盾。
  - **修复**(commit 见 §6 F1):`dialTarget` 把 WaitAnswer 放入 goroutine 与 `attemptCtx` 竞速,
    超时先给 250ms 宽限窗(振铃/取消场景走回原有顺序分类,保证 `aLeg.Respond` 不被两个
    goroutine 并发调用),宽限到期即放弃本腿按 failRing 分类并转移;goroutine 自生自灭
    (迟到响应走 CANCEL 流程,迟到 2xx 由它 ACK+BYE 拆除;黑洞时按 RFC 3261 §9.1 无
    CANCEL 可发,事务自生自灭于 Timer_B,与修复前相同的后台资源占用,但不再阻塞主流程)。
    回归测试:`TestBridgeFailoverSilentTarget`、`TestBridgeCancelSilentTarget`(sig/b2bua_test.go)。

### T5 486 透传 ✅ PASS(狩猎语义确认)

- carrier-a 回 486 → SBC **继续尝试下一个目标**(顺序狩猎,设计行为:真实码在所有目标耗尽后
  才透传)→ carrier-b 也回 486 → 486 毫秒级透传给主叫(FS 通道 ~3s 内销毁)。
- 证据:两个 UAS 均收到 INVITE 并回 486;SBC 日志两条 `Invite failed with response: 486 Busy Here`(同一毫秒)。
- 注意:若后续目标为黑洞,486 透传同样受 F1 的 32s 延迟影响(实测一次:FS 通道 32s 后才销毁)。

### T6 无路由 404 ✅ PASS

- FS 拨 82001(无匹配路由)→ SBC `rejected invite code=404 reason="Not Found" source=192.168.31.5:5080`
  (日志);FS 通道挂断原因 **UNALLOCATED_NUMBER**(404 的正确映射)。

### T7 RTP 静默超时拆除 ✅ PASS

- SIPp 静默 UAC(无 RTP/RTCP)→ 9196(FS echo,不主动发声)→ 全零媒体。
- **BYE 在呼叫建立后 20.012s 到达**(rtp_timeout=20s),SBC 主动拆除两腿,资源归零。

### T8 admin 踢话 ✅ PASS

- 通话中 `DELETE /api/calls/{id}` → **204**;SIPp 收 BYE、FS 通道销毁、`/api/calls` 清空。

### T9 OPTIONS 与盾牌自动封禁 ✅ PASS

- 已知 peer(127.0.0.2)OPTIONS → **200 OK**。
- 未知源(127.0.0.1)OPTIONS ×11 → **全部静默丢弃**(SBC 日志 `dropping request from
  unidentified source`);第 10 次触发 `shield auto-banned source=127.0.0.1 failures=10
  duration=1h`;指标 `freesbc_shield_banned_current 0→1`、`drops_total{reason="banned"} 0→1`(第 11 个包)。

### T10 并发压测 ✅ PASS

- SIPp UAC 30 路 @ 5cps → 9197。**30/30 成功,0 失败**。
- 峰值曲线:`calls=29 / ports=58`(03:37:23),上升 10→21→29,回落 19→8→0;
  端口占用严格等于 2×呼叫数,结束后全部归零(无泄漏)。

### T11 SRTP(SDES)互通 ⏭️ SKIP(环境限制)

- 前置检查:`ldd /usr/local/freeswitch/bin/freeswitch` 无 libsrtp2;二进制/mod_sofia 无 srtp 符号
  —— 该 FreeSWITCH 构建不支持 SDES SRTP。测试需重编译 FS(libsrtp2-dev)。
- SBC 侧 SRTP 能力(SDES 协商、SRTP↔RTP 中继)由单元测试覆盖(sig/b2bua_test.go 的 SRTP 用例、
  media/srtp 相关测试),本次未做真实互通验证。

### T12 通话中热重载 ✅ PASS

- 通话进行中改 `peer_cooldown: 30s→60s` → 日志 `config reloaded`;同一呼叫(call-id 不变)
  继续存活,RTP 不中断,正常挂断。配置已还原。

## 5. 汇总表

| # | 场景 | 结果 | 关键数据 |
|---|---|---|---|
| T1 | 出局基本呼叫 | ✅ | 9 剥除、CLI 透传、SDP 改写、RTP 四向、指标归零 |
| T2 | 入局基本呼叫 | ✅ | 注册表生命周期完整、RTP 双向 |
| T3 | 振铃超时 | ✅ | CANCEL 4.002s/4.005s、408 回主叫 |
| T4a | 故障转移(振铃) | ✅ | 4.001s CANCEL 后 2ms 接续 |
| T4b | 故障转移(黑洞) | ✅(修复后复验) | 修复前 32.004s → 修复后 **4.256s** |
| T5 | 486 透传 | ✅ | 狩猎语义;全目标响应时毫秒级透传 |
| T6 | 无路由 404 | ✅ | FS 挂断原因 UNALLOCATED_NUMBER |
| T7 | RTP 静默超时 | ✅ | 20.012s 主动 BYE |
| T8 | admin 踢话 | ✅ | DELETE 204、两腿 BYE |
| T9 | OPTIONS/盾牌 | ✅ | 已知 200;未知静默;10 次封禁生效 |
| T10 | 30 路并发 | ✅ | 30/30,峰值 29 路/58 端口,无泄漏 |
| T11 | SRTP 互通 | ⏭️ | FS 无 libsrtp,环境限制 |
| T12 | 热重载 | ✅ | 通话中重载不中断 |

## 6. 发现的问题

### F1(重要,已修复):黑洞(零响应)目标的故障转移延迟约 32s,ring_timeout 不生效

- **现象**:T4b 修复前实测 32.004s;T5 附带观察一致。修复后 T4b 复验 **4.256s**。
- **根因**:sipgo v1.4.3 `inviteCancel()`(dialog_client.go:355-366)在目标从未发送任何响应时
  阻塞至事务 Timer_B,不发送 CANCEL、不返回 ctx.Err();FreeSBC `placeCall` 的 4s ring 预算
  (b2bua.go:817)因此形同虚设。目标只要发过 1xx(哪怕 100 Trying),行为即正常(T3/T4a 验证)。
- **修复**(`sig/b2bua.go` `dialTarget`):WaitAnswer 移入 goroutine,主流程 `select` 在
  `waited` 与 `attemptCtx.Done()` 间竞速;deadline 先到则给 250ms 宽限窗等 goroutine 交付
  (振铃场景毫秒级交付,分类走原有顺序路径,避免两个 goroutine 并发 `aLeg.Respond`),宽限
  到期即放弃本腿按 failRing 分类(黑洞端点按原语义冷却);goroutine 保留 ackThenBye 逻辑
  拆除迟到 2xx 的幻影呼叫。回归测试:`TestBridgeFailoverSilentTarget`(2s ring_timeout 下
  ~2.3s 完成转移并断言黑洞端点被冷却、RTP 全通)、`TestBridgeCancelSilentTarget`(主叫取消
  快速收 487、循环停止、端点不冷却)。
- **注意**:黑洞时 RFC 3261 §9.1 禁止在无响应前发 CANCEL,放弃的 INVITE 事务仍会在后台
  重传至 Timer_B(~32s)——与修复前资源占用相同,但不再阻塞故障转移。

### F2(信息):媒体 latch 为 fail-closed,不向未 latch 的腿转发

- **现象**:T1 首轮,FS→SBC 的 RTP 被 SBC 丢弃 361 包(SBC→SIPp 方向 0 包),因为 SIPp
  (`-rtp_echo`)被动等待、从未先发 RTP,B 腿 latch 未建立。
- **代码出处**:`media/relay.go:72`(`if dst := outLatch.target(); dst != nil`)——只向已 latch
  的远端转发;`media/session.go:71-92` 首包才建立 latch。这是**有意的加固设计**
  (防 RTP 劫持,fail-closed),但与常见 SBC 的「先按 SDP 地址转发、latch 后切换」不同。
- **影响**:若某侧终端完全被动等对方先发媒体(如纯回声器),该侧在对方发流前收不到任何
  媒体。真实话机应答后通常立即发静音/舒适噪声包,影响有限。
- **建议**:维持现状(安全优先)或在文档中明确该语义。

### 观察(非缺陷)

- SIPp 自定义场景含 `<exec>` 时不自发 ACK;SBC 以 200 重传应对,行为正确。
- FS `originate` 在被叫侧无进展时 ~7-8s 自行 CANCEL(其自身行为,与 SBC 无关)。
- SIPp teardown 时偶发 `Failed to delete FD from epoll, errno = 1`(SIPp 自身噪音,不影响结果)。
- 被放弃的 INVITE 客户端事务在后台重传至 Timer_B(32s)才消亡,期间占用少量资源(与 F1 同源)。

## 7. 已运行命令及实际结果(摘选)

```sh
# 环境准备
sudo apt install -y build-essential cmake libpcap-dev libssl-dev libncurses-dev
git clone --depth 1 https://github.com/SIPp/sipp /tmp/sipp && cd /tmp/sipp \
  && git submodule update --init && cmake -B build . && cmake --build build -j   # → sipp c496186-TLS-PCAP
sudo ip addr add 127.0.0.2/8 dev lo
./freesbc check -c test/interop/sbc.yaml                                        # → config OK

# T1(代表)实际输出:
#   /api/calls(mid): [{"duration_seconds":7,"from":"internal-pbx","to":"carrier-a",…}]
#   metrics(mid): freesbc_active_calls 1 / media_ports_in_use 2
#   RTP(lo pcap):FS 腿 597/362 双向;SIPp 腿 362/362 双向
#   sipp: Successful call 1 / Failed call 0

# T7 实际输出:BYE 到达 = 呼叫建立后 20.012s(rtp_timeout=20s)
# T10 实际输出:Successful 30 / Failed 0;峰值 calls=29 ports=58;结束 0/0
```

## 8. 覆盖范围

- SIP over UDP 双向呼叫、B2BUA 号码变换/CLI 透传/SDP 改写、RTP 中继(双向、latching)、
  RTCP 端口配对;振铃超时、顺序故障转移(振铃/黑洞两型)、真实码透传(486/404)与狩猎语义、
  408/404/486/487 回主叫;CANCEL/BYE/踢话/RTP 超时四种拆除路径;
  盾牌(未知源静默、自动封禁);admin API 与 metrics;30 路并发;热重载。

## 9. 未覆盖内容与证据缺口

- **SRTP(SDES)互通**(T11):FreeSWITCH 无 libsrtp,需重编译 FS 或用支持 SRTP 的对端补测。
- TLS/TCP 传输、WS 未测(FreeSWITCH 支持 TLS/TCP,可作为后续场景)。
- 注册式 trunk(outbound REGISTER + digest 鉴权)未测(SIPp 支持 digest,可后续补)。
- 会话计时器刷新(4028)、100rel/PRACK 的真实互通未测(仅验证了 420/422 前置闸门代码路径)。
- 媒体超过 rtp_timeout 后、以及大规模(百路以上)下的表现未压测。
- 全部单机 loopback/本机路由;跨主机/真实 NAT 场景未覆盖。
- `public_ip: auto`(STUN)未实现,天然未测。

## 10. 建议

1. ~~优先修复 F1~~ ✅ **已修复并回归**(sig/b2bua.go dialTarget 竞速 + 250ms 宽限,
   `TestBridgeFailoverSilentTarget`/`TestBridgeCancelSilentTarget`,T4b 实景复验 4.256s)。
2. FS 重编译(libsrtp2-dev)后补跑 T11 SRTP 场景;或改用 Asterisk/Kamailio 做 SRTP 对端。
3. 考虑把本套场景纳入 CI(设计文档 freesbc-allinone-design.md §8 的既定目标):SIPp XML +
   测试配置已随仓库提交,依赖仅为 SIPp 二进制与一个 FreeSWITCH/Asterisk 实例。
