# FreeSBC 安全整改任务清单

- 生成日期：2026-08-31 ｜ 基线 HEAD：`7fe89d9`
- 输入文档：`docs/SECURITY-AUDIT-20260826.md`（发现编号 F-xx/D-xx）、`docs/REMEDIATION-PLAN.md`（任务卡 T-01…T-37，含每卡完整规格：红测试/允许改动/涉及符号）、`docs/SECURITY-REVIEW-20260831.md`（新增 S-01…S-05）
- 本文件只定**执行序列、优先级与依赖**；每张卡的完整规格见 REMEDIATION-PLAN §3。
- 状态：`[ ]` 未开始 ｜ `[x]` 完成
- 通用验收（每卡适用）：红测试转绿 + `go test ./... -race` + `go vet ./...` 无新增告警。
  ⚠️ 已知本机 `go test ./sig/` 存在基线同病 flaky（见 SECURITY-REVIEW §2.4，~3.2s 签名，非本次修复引入）——单卡验收用 `-run` 定向跑，全量套件失败时先对照基线判断。

---

## P0 —— 公网部署阻断（代码，发布前必须完成）

**顺序约束**：T-01 先行（入口收敛，缩小后续所有任务的攻击面）；shield 链 T-03 → T-04 → T-02 严格有序（同文件同函数区）；sig 链 T-05、T-06 与 shield 链**可并行**（不同文件）；T-06 先于 P1 的 T-18。

1. `[x]` **T-01**（F-01/F-10）SIP 入口前置过滤：非 peer 源字节在解析前丢弃（`WithTransportLayerReadFilter`）
   - 涉及：sig/server.go、新 sig/readfilter.go
   - 依赖：无（第一个做）
2. `[x]` **T-03**（F-05）banList 硬上限（建议 64k，超限拒绝并计数）
   - 涉及：shield/banlist.go、shield/shield.go
   - 依赖：T-01（攻击面收敛后测试更稳定，非硬依赖）
3. `[x]` **T-04**（F-03）scanner 判定移到限速之后 + nft exec 单 worker 有界队列 + 2s 超时
   - 涉及：shield/shield.go、shield/banlist.go、shield/nftables.go
   - 依赖：T-03（同一 Check 函数区，避免冲突性重构）
4. `[x]` **T-02**（F-04）nft 规则限定 SIP 端口/协议 + UDP 单包判定仅内存 ban + `DELETE /api/bans/{ip}` unban
   - 涉及：shield/nftables.go、shield/shield.go（Check 增传输类型参数）、admin/server.go、admin/api.go
   - 依赖：T-04（Check 签名调整叠在 T-04 重排之后）
5. `[x]` **T-05**（F-02）SIP TCP/TLS listener 包装：全局连接上限 + 每连接空闲/读超时
   - 涉及：sig/server.go、新 sig/listenerlimit.go
   - 依赖：无（与 2-4 并行）
6. `[x]` **T-06**（F-06，含 D6-8）`peers.<name>.max_concurrent_calls` + 全局上限，超限 503+Retry-After
   - 涉及：config/schema.go、config/validate.go、sig/b2bua.go、sig/server.go
   - 依赖：无（与 2-4 并行）；完成后 T-18 才生效意义

### P0 —— 部署闸门（运维项，随 P0 代码一并交付；无代码依赖，可随时写）

7. `[x]` **G-1**（F-07 缓解）公网暴露策略文档：公网仅 tcp/tls 监听（或上游 ACL+uRPF）；明示「UDP 下源 IP 伪造 = 完整 peer 信任」边界。代码级修复（入向 digest 质询）在后期清单，需产品决策。
8. `[x]` **G-2**（F-14 缓解）admin 部署基线文档：仅绑 loopback；非 loopback 部署清单（TLS 反代/防火墙）在 T-26 落地前的临时闸门。

---

## P1 —— 紧随其后（7 天内批次）

**顺序约束**：T-07 优先（密钥泄露入口）；S-batch 与 T-07 同文件（b2bua.go），建议 T-07 后依次合入；T-08 需同步改造 pumpTransform 测试泵。

9. `[x]` **T-07**（F-08）refresh re-INVITE 补 dialog 校验（Call-ID+双 tag），不符 481
   - 涉及：sig/b2bua.go:127-151、sig/callsdp.go、sig/timers.go
10. `[x]` **S-batch**（本次审查新增，见 SECURITY-REVIEW §2.2）：
    - **S-02** OnResponse 先查 `abandoned`，命中即 return nil（一行短路，堵死 grace 竞态与 select 随机性两条入口）+ 补回归：迟到 18x 不触发 aLeg.Respond、grace 边缘 -race 干净
    - **S-01** 孤儿 goroutine 加 `defer recover()`（Error 日志），panic 不再杀进程 + 注入 panic 断言进程存活
    - **S-04** `ackThenBye` 的 Ack 换 5s 级 `byeContext`（不再接受 Background ctx）
    - 涉及：sig/b2bua.go（dialTarget/ackThenBye 区）；三张卡同函数区，按 S-02 → S-01 → S-04 顺序合入
    - 依赖：T-06（同文件上游，减少冲突）；补测 raced-2xx teardown、grace 边缘、abandon 后晚到响应
11. `[x]` **T-08**（F-09）SRTP/SRTCP 防重放（窗口 64/128），pumpTransform 重发泵同步改造
    - 涉及：media/srtp.go、media/srtp_relay_test.go、media/srtp_test.go
12. `[x]` **T-09**（F-14 代码面）admin 认证：缺 Authorization 头直接 401 跳过 bcrypt + per-IP 失败限速（10/分钟→429）
    - 涉及：admin/server.go
13. `[x]` **T-15**（F-15）admin 凭据每请求从 `store.Current()` 读取（热重载吊销旧口令）
    - 涉及：admin/server.go、main.go（如需）
    - 依赖：T-09 之后（同函数 requireAuth）
14. `[x]` **T-18**（F-19）peer 宽松限速（可配 `shield.peer_rate_limit`，缺省 200/s per_ip），保持 scanner/ban 豁免语义
    - 涉及：shield/shield.go、shield/ratelimit.go、config
    - 依赖：T-06 已落地（配额先于限速）；S-03（静默目标事务 ×K 并行）是本条紧迫性依据
15. `[x]` **T-26**（D4-6）admin.listen 非 loopback 默认拒绝（`admin.allow_remote` 显式放行）+ bcrypt cost ≥10 强制
    - 涉及：config/validate.go、config/schema.go
    - 依赖：无；落地后 G-2 由文档闸门升级为代码闸门
16. `[x]` **T-26b**（本次新增，超出复核计划——局域网访问需求）admin 原生 TLS：`admin.tls_cert`/`tls_key` 可选（同设同撤），配置即 HTTPS（MinVersion 1.2）；allow_remote 无 TLS 时启动打显著 WARN
    - 涉及：config/schema.go、config/validate.go、admin/server.go、sbc.example.yaml
    - 注：原计划 T-17（SIP 信令面 TLS）不受影响，仍在第三梯队；admin TLS 原本只有 G-2 文档的「TLS 反代」路线，本卡为原生实现

---

## P2 —— 第三梯队（注入/泄露/配置面）

**顺序约束**：T-12 依赖 T-01；T-17 先于 T-19（schema 惯例）。

16. `[ ]` **T-10**（F-17）全链路 IP 规范化（sourceAddr 统一 Unmap + nft 选集双保险）
17. `[x]` **T-11**（F-16）allowed_ips 校验：非空 + 宽度上限 + 规范前缀（存 Masked）
    - 宽度下限实现取 **IPv4 /8、IPv6 /32**（复核建议 /16//48 的放宽：本仓示例配置自带 10.0.0.0/8 peer，收紧会打翻官方示例；/8、/32 是真实分配边界，0.0.0.0/0 等灾难性宽度仍拒绝）
    - 波及夹具：admin minimalConfigYAML、sig skipUnregisteredCfg / register_test 模板补 allowed_ips（register 测试 carrier 用与 caller 不重叠的前缀，否则 identify 串台）
18. `[ ]` **T-13**（F-12）身份字段清洗：剔 CR/LF 与引号破坏；被叫号码白名单
19. `[ ]` **T-14**（F-11）SDP relay 段属性白名单（剔 candidate/fingerprint/ice-*），o= 标识重写
20. `[ ]` **T-12**（F-10 残余）杂散 response 静默计数（UnhandledResponseHandler）——依赖 T-01
21. `[x]` **T-16**（F-18）敏感响应 `Cache-Control: no-store`（recoverMW 统一注入，/healthz 豁免）
22. `[x]` **T-17**（F-13）TLS 凭据配置面：入向 tls_cert/tls_key/client_ca（mTLS 可选）+ 出向 per-peer CA/客户端证书 + 显式 TLS1.2
23. `[x]` **T-19**（F-20）digest realm 钉扎（PeerAuth.realm 不匹配即认证失败）——依赖 T-17

---

## P2 —— 第四梯队（Low 清单，可并行）

24. `[x]` T-20（D1-8）全部 SIP handler panic recover + 必备头校验（缺 To/From 回 400）
25. `[ ]` T-21（D7-9）dropUnidentified 日志降 Debug + 周期聚合
26. `[x]` T-22（D5-4）watchdog 仅在 SRTP 认证后刷新 lastRx
27. `[ ]` T-23（D6-9）重复 Call-ID 第二路呼叫回 482
28. `[x]` T-24（D3-4）admin http.Server 补 Idle/Read/WriteTimeout
29. `[ ]` T-25（D3-2）安全响应头基线（nosniff/XFO/Referrer-Policy/最小 CSP）
30. `[ ]` T-27（D7-11）shield 参数上限校验（rate ≤1000、ban 时长 ≥1s）
31. `[x]` T-28（D8-1）DNS 解析超时 + singleflight + 失败短缓存 ┐
32. `[x]` T-29（D8-2）SRV 语义过滤（Target "."、port 0）        ├ 同文件 sig/resolve.go，同一批
33. `[x]` T-30（D8-4）tls 传输回退端口 5061                     ┘
34. `[ ]` T-31（D4-7）Load 文件大小上限 1MiB ┐ 同文件 config/loader.go，同一批
35. `[ ]` T-32（D8-7）配置文件权限检查（含凭据时拒绝 group/other 可读）┘
36. `[ ]` T-33（D4-3）写回文件权限收紧 0600 ┐ 同文件 admin/config_write.go，同一批
37. `[ ]` T-34（D4-5）symlink 拒写 + 目录 fsync             ┘
38. `[ ]` T-36（D7-7）nft 表实例隔离 ┐
39. `[ ]` T-37（D7-8）nft 二进制路径可配  ├ 同文件 shield/nftables.go，与 T-02 同文件——建议 T-02 合入后再做，顺序 T-36 → T-37 → T-35
40. `[ ]` T-35（D7-6）nftables 模式热重载生效 ┘

---

## 后期考虑（无把握 / 低优先级 / 需产品决策，暂不排期）

> 完整理由见 REMEDIATION-PLAN §5 挂起清单与驳回清单。

| 项 | 状态 | 缺什么才能立项 |
|---|---|---|
| F-07 代码级（入向 digest 质询/mTLS） | 挂起 | 产品决策：schema 与质询流程定义 |
| F-21（DNS 信任链/pinning） | 挂起 | T-17 落地后重估观测点 |
| D4-2（goccy 别名炸弹） | 挂起 | Go 环境 PoC 确认崩溃复现（工具链现已可用，可补） |
| D4-4（PUT TOCTOU） | 挂起 | 串行化设计决策 |
| D4-8（fsnotify 静默死亡） | 挂起 | 需重构暴露注入点 |
| D3-5（Call-ID 无长度上限） | 挂起 | T-01 落地后重估残余攻击面 |
| D5-3（strict 仅 IP arming） | 挂起 | SSRC 预学习 vs NAT 兼容的产品取舍 |
| D5-7（RTCP CNAME 透传） | 挂起 | 运营商互操作验证 |
| D7-10（sipsak 误杀） | 挂起 | 指纹策略决策 |
| D8-6（root/降权 systemd 样例） | 挂起 | 部署文档工作项，随 G-1/G-2 一起交付 |
| S-05（100 Trying 置 responded） | 记录 | 非安全项，健康机制噪音 |
| sig 包 flaky 根因调查 | 记录 | 基线同病、环境相关；单卡验收用 `-run` 规避，CI 引入前需查清 |
| D8-5（CI/SBOM/签名）、D2-7（SSRF-by-config） | 驳回 | 见 REMEDIATION-PLAN §4（前者建议独立 ops 任务跟踪） |

---

## 执行总览

```
P0:  T-01 ──▶ T-03 ──▶ T-04 ──▶ T-02          （shield 链，串行）
             └──（并行）──▶ T-05               （sig listener）
             └──（并行）──▶ T-06               （per-peer 配额）
     G-1 / G-2 文档可随时并行
P1:  T-07 ──▶ S-02 ──▶ S-01 ──▶ S-04 ──▶ T-08 ──▶ T-09 ──▶ T-15 ──▶ T-18 ──▶ T-26
P2:  第三梯队 T-10…T-19（T-12 依赖 T-01；T-17→T-19）
     第四梯队 T-20…T-37（按同文件分组：resolve.go ×3、loader.go ×2、config_write.go ×2、nftables.go ×3）
```

> 数据来源与每卡规格：`docs/REMEDIATION-PLAN.md`；本次增量发现：`docs/SECURITY-REVIEW-20260831.md` §2.2。
