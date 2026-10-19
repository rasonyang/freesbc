# 正式三机压测（issue #109）：操作员手册

## 实例规格（都是抢占式，可用区 cn-wulanchabu-b，同一个安全组）

| 主机 | 角色 | 规格 | vCPU / 内存 | 网络 |
|---|---|---|---|---|
| A | loadgen，总控 | 计算型，独享 vCPU（`ecs.c9i.2xlarge`，Intel Xeon 6982P-C；或 `ecs.c8a.2xlarge`，AMD EPYC 9T24，2026-10-18 正式压测用的是它），系统盘 40 GiB | 8 / 16 GiB | 公网 vSwitch `172.30.96.0/20`，主 IP + 两个辅助 IP（可选再加一个给 M06），地址见 `plan.env` |
| B | sbc，FreeSBC（被测对象） | Intel 1:2 计算型（`ecs.c9i.xlarge`，Intel Xeon 6982P-C），**必须支持至少 2 块 ENI**；不设 `MemoryMax`（机器本身 8 GiB） | 4 / 8 GiB，系统盘 40 GiB | eth0 在公网 vSwitch，eth1（第二块 ENI）在私网 vSwitch |
| C | switch，SIPp + FreeSWITCH + Asterisk | 计算型，独享 vCPU（`ecs.c9i.2xlarge`，Intel Xeon 6982P-C），系统盘 40 GiB | 8 / 16 GiB | 只在私网 vSwitch；要有公网 IP（ssh、apt、docker、github 用，压测不使用） |

竞品的机器是 Xeon X5670 6C/12T 2.93 GHz、8 GB、128 GB SSD、Debian 10；磁盘大小不是变量（FreeSBC 几乎不碰磁盘）。B 的核数比 X5670 少（2 核 4 线程 vs 6 核 12 线程，Xeon 6982P-C vs 2010 年的 Westmere），但每核快得多，所以总算力大致相当到略低。报告里会记录 `lscpu` 和 OS 差异（这里 Ubuntu 24.04，竞品 Debian 10 / 内核 4.19）。`GOMEMLIMIT` 来自 `plan.env` 的 `B_GOMEMLIMIT`（默认 6GiB）。

安全组：组内全放行；公网只放 tcp 22，来源是你的出口 IP。

## 笔记本上做（一次）

1. 控制台（细节见 `STEPS.md` R01）：在同一可用区新建**私网 vSwitch**（CIDR 自选，例如 `172.16.0.0/24`）；按上表建 A、B、C（C 放私网 vSwitch，B 放公网 vSwitch）；给 B 在私网 vSwitch 建第二块 ENI 并挂载；在 A 的主网卡上分配两个辅助 IP。
2. 填 `plan.env` 里的占位符（`__ASSIGN_IN_CONSOLE__`，没填 `provision.sh` 会拒绝运行）：
   `PRIV_SUBNET_CIDR`、`PRIV_PREFIX_LEN`、`B_PRIV_IP`（B 的 eth1 地址）、`C_IP`（C 的私网地址）。
   另外：`DOCKER_REGISTRY_MIRROR`（C 拉 FreeSWITCH 镜像用，阿里云控制台 容器镜像服务 → 镜像加速器 里你账号的 URL；空表示不用）、
   可选 `A_LOADGEN2_IP`（M06 的第二个客户端源地址）。
3. 把三台的公网 IP 写进笔记本 `~/.ssh/config` 的 `ecs-A`、`ecs-B`、`ecs-C`（见 `STEPS.md`）。
4. 拷共享 pem，并同步套件（缺 pem 时自检会 FAIL，互相 ssh 都不可用）：

```sh
cd "$(git rev-parse --show-toplevel)"   # the freesbc checkout
for h in ecs-A ecs-B ecs-C; do scp ~/.ssh/aicc-dev-ecs.pem $h:.ssh/ && ssh $h chmod 600 .ssh/aicc-dev-ecs.pem; done
{ git rev-parse --short HEAD | tr -d '\n'; [ -z "$(git status --porcelain -- . ':!COMMIT')" ] || printf -- -dirty; } > COMMIT
for h in ecs-A ecs-B ecs-C; do ssh $h 'sudo install -d -o ecs-user -g ecs-user /opt/freesbc'; rsync -az --delete --exclude .git --exclude test/perf/out --exclude results ./ $h:/opt/freesbc/; done
```

注意：`provision.sh` 装好之前，A、B、C 上还没有 `loadgen`/`sbc`/`switch` 这些 ssh 别名。主机之间互连先用
`ssh -i ~/.ssh/aicc-dev-ecs.pem ecs-user@<plan.env 里的私网 IP>`；provision 之后别名才可用。
旧机器上遗留的 `~/.ssh/aicc-dev-ecs.pem.pub` 若和 pem 不匹配，OpenSSH 会提供错误的 key：自检会 FAIL 并给出办法（把它改名）。

5. 只在 A 上装好并登录 `gh`（pi 用它往 #109 发评论；provision.sh 不装它，A 重建后要重做）。用一个只授权 `rasonyang/freesbc`、只有 Issues 读写权限的 fine-grained token，粘贴进去后按 Ctrl-D（token 不进 shell 历史，也不写进任何套件文件）：

```sh
ssh ecs-A 'command -v gh >/dev/null || sudo apt-get install -y gh'
ssh -t ecs-A 'gh auth login --with-token && gh auth status'
```

A 上 github.com 时通时不通，所以不用浏览器设备码登录；`--with-token` 只访问 api.github.com。测完后执行 `ssh ecs-A gh auth logout` 退出登录。

## 当天：三台各贴一条

三台各开一个终端：`ssh ecs-A` / `ecs-B` / `ecs-C`，启动 pi，贴对应的提示词。三台可以同时贴。

```sh
cd /opt/freesbc/test/perf/hosts/agents/loadgen && pi   # A
cd /opt/freesbc/test/perf/hosts/agents/sbc && pi       # B
cd /opt/freesbc/test/perf/hosts/agents/switch && pi    # C
```

分工：压测期间限制 FreeSBC 核数（M03 的 2 核和 1 核）**由 A 通过 ssh 调用 `ssh sbc sudo sbc-cores N` 完成**，B 的 agent 不需要动手，只负责装好、保持可用、按 A 的请求查日志。

### A（loadgen，总控）

```
你是 FreeSBC 正式压测（issue #109）的总控 A（loadgen）。今天的目标：尽可能把 /opt/freesbc/test/perf/hosts/MEASURE.md 从头到尾跑完，收工前把当天结果发到 #109，并启动 8 小时 soak。

先读 /opt/freesbc/results/progress.md（没有就建），再读 plan.env、STEPS.md、MEASURE.md 和本目录的 AGENTS.md。B（sbc）和 C（switch）由各自的 pi 装机，你可以用 ssh（装好前用 ssh -i ~/.ssh/aicc-dev-ecs.pem ecs-user@<plan.env 里的 IP>，装好后用别名 sbc / switch）检查和协助，B 的核数限制由你用 ssh sbc sudo sbc-cores N 来设。

1. 确保 A 装好（provision.sh loadgen）；SIPp 源码包 C 可以自己从 github 下载，下载失败再由你 fetch-sipp 后 scp 过去。等 B、C 就绪（自检全部 PASS）。
2. 按 MEASURE.md 的顺序做 M03（竞品场景，整机 4 vCPU / 2 核 / 1 核）、M01、M02、M04、M05、M06、M07（含 #170 的 RSS 每 CPS），每项按那里的命令、通过标准和记录要求做，结果追加到 results/<date>/measure-results.md，并用 progress.sh 更新 M0x。长任务用 nohup 或 tmux 放后台，写日志，轮询；任何一次工具调用都不要阻塞超过一两分钟。
3. 用 M02 的最大并发算出 soak 的负载（70%，取 50 的整数倍），18:00 前后用 m08.sh 在后台启动 8 小时 soak，确认它跑起来。
4. 遇到问题自己排查、修复、重试。可以改 /opt/freesbc/test/perf/ 下的脚本和配置（先备份为 <file>.orig-<日期>，在 notes.md 记下改了什么、为什么），但不要改 FreeSBC 的 Go 源码；怀疑是 FreeSBC 的 bug 就记录证据（PROBLEM 行）。不要为了让数字好看而调参，调过的参数必须写进报告。
5. 收工报告：运行 test/perf/hosts/daily-report.sh 生成 summary.md（含 M03 与竞品的对照表和每个 run 的 runcheck 结论）；补充 MEASURE.md 里每项要求记录的数字、pprof 结论、遇到的问题。确认里面没有公网 IP、密钥、口令后，用 gh issue comment 109 --repo rasonyang/freesbc --body-file <summary.md 路径> 发到 #109。然后 progress.sh set R18 done，再运行一次 daily-report.sh --retar 重新打包。

不要输出任何密钥或公网 IP；gh 只用来在 #109 发评论（今天一条日报，soak 结束后一条 soak 报告）；不要动云资源，不要关机，不要删除结果。最后告诉我评论链接和 soak 的开始时间。
```

### 第二天早上：还是 A 上的 pi（可能是同一个会话，也可能是新开的，贴这一条）

```
继续 FreeSBC 正式压测（#109）。soak 应该已结束：先读 /opt/freesbc/results/progress.md 和 results/m08.log，用 MEASURE.md 的 M08 一节检查结果：m08.sh --report <soak 的 run 目录>、soakcheck.sh、runcheck.sh。如果主机在 soak 中被回收，写明时间和已跑时长。把 soak-report.md 补上 goroutines / RSS / fds / ports 的首末四分位数和结论（通过或不通过），确认没有公网 IP、密钥、口令后发到 #109（gh issue comment 109 --repo rasonyang/freesbc --body-file ...），progress.sh set M08 done|failed，再运行 daily-report.sh --retar <压测当天日期> 重新打包。完成后告诉我评论链接。规则同昨天：不改 FreeSBC 源码，不输出密钥和公网 IP，gh 只发这一条评论，不动云资源。
```

### B（sbc）

```
你是 FreeSBC 正式压测的 sbc 主机 B（被测对象：4 vCPU / 8 GiB，核数比竞品少、每核更快）。今天的目标：让这台机器上的 FreeSBC 装好、调优、自检全部通过，并在 A 压测期间一直可用。

先读本目录的 AGENTS.md、/opt/freesbc/test/perf/hosts/plan.env、STEPS.md 的 R04 和 MEASURE.md，再看共享进度（装好别名前：ssh -i ~/.ssh/aicc-dev-ecs.pem ecs-user@<plan.env 里 A_IP> cat /opt/freesbc/results/progress.md）。

1. 装好或检查 FreeSBC（provision.sh sbc）：eth1（私网 vSwitch，B_PRIV_IP）配好且没有默认路由，ulimit、rtp 10000-59999、GOMEMLIMIT 来自 plan.env，自检全部 PASS；遇到问题自己排查、修复、重试。把 lscpu、内存、内核版本写进 notes.md（对照竞品的 X5670 / 8 GB / Debian 10）。
2. 确认 freesbc-use sipp|fs 能切换后端配置，sbc-cores 1|2|all 能限制核数并恢复，A 能 ssh 过来。
3. 把状态写进 /opt/freesbc/results/sbc/notes.md，再通过 A 更新共享进度：progress.sh set R04 done "<一行>"（没完成就 failed 并写原因）。
4. 之后保持待命：核数限制由 A 通过 ssh 设置，你不要自己改；不要重启或停掉 freesbc；A 来请求时帮忙查日志、journal、dmesg、UDP 丢包。

可以改 /opt/freesbc/test/perf/ 下的脚本和配置（先备份，并在 notes.md 记录），不要改 FreeSBC 的 Go 源码；不要输出任何密钥或公网 IP；不要用 gh；不要动云资源，不要关机。完成后用几行话汇报状态。
```

### C（switch）

```
你是 FreeSBC 正式压测的 switch 主机 C（私网 vSwitch，8 vCPU / 16 GiB）。今天的目标：让 FreeSWITCH、Asterisk 和 SIPp UAS 在这台机器上装好、调优、自检全部通过，并在 A 压测期间一直可用。

先读本目录的 AGENTS.md、/opt/freesbc/test/perf/hosts/plan.env、STEPS.md 的 R05 和 MEASURE.md 的 M06，再看共享进度（装好别名前：ssh -i ~/.ssh/aicc-dev-ecs.pem ecs-user@<plan.env 里 A_IP> cat /opt/freesbc/results/progress.md）。

1. 装好或检查这台机器（provision.sh switch）。docker.io 从 apt 装；FreeSWITCH 镜像默认 safarov/freeswitch:latest，经 plan.env 的 DOCKER_REGISTRY_MIRROR（阿里云镜像加速器）拉取，provision.sh 会写 /etc/docker/daemon.json；拉不到可以用 FS_IMAGE_TAR（docker save 文件）。C 能访问 github，SIPp 源码包直接下载（失败再由 A fetch-sipp 后 scp 到 /var/tmp/）。FreeSWITCH 的 sessions-per-second、max-sessions 要够 1000+ CPS 和几千并发，RTP 端口范围放宽，日志级别调低；记录实际的 FreeSWITCH 版本。
2. 自检全部 PASS 后，确认 FreeSWITCH 的 perf profile（5090）、Asterisk（5080）都在监听，5060 留给 SIPp UAS，ulimit 够大，且这些服务只接受来自 B_PRIV_IP 的流量。
3. 把状态（包括 FreeSWITCH 版本）写进 /opt/freesbc/results/switch/notes.md，再通过 A 更新共享进度：progress.sh set R05 done "<一行>"（没完成就 failed 并写原因）。
4. 之后保持待命：A 会来启动 SIPp UAS、清 FreeSWITCH 注册、挂载 sshfs、查日志和 CPU，不要停掉这些服务。

可以改 /opt/freesbc/test/perf/ 下的脚本和配置（先备份，并在 notes.md 记录），不要改 FreeSBC 的 Go 源码；不要输出任何密钥或公网 IP；不要用 gh；不要动云资源，不要关机。完成后用几行话汇报状态。
```

## 事后

- 拉结果（笔记本）：`test/perf/hosts/pull-results.sh --all`。A 的结果在 `~/freesbc-perf-results/`，B、C 只拉各自角色子目录到 `hosts/sbc/`、`hosts/switch/`，不会覆盖 A 的 `progress.md`、日期目录和压缩包。
- 笔记本定时同步（只读，不会改动主机）：跑一次 `test/perf/hosts/sync-results.sh --install`，之后每 10 分钟（和登录时）自动把 A 的结果、A 的 `out/`（不含 pcap，到 `hosts/loadgen-out/`）和三台机器各自的套件快照（`kit/<角色>/`，含 agent 的现场改动和 `*.orig-<日期>` 备份）拉到 `~/freesbc-perf-results/`。主机宕机或被回收，最多丢 10 分钟。`--status` 看状态和 `sync.log`，`--uninstall` 移除。
- 清理 A、B 上 agent 加的临时 key：`ssh ecs-A cat .ssh/authorized_keys`，只保留 pem 的公钥和云厂商密钥对的条目。
- pi 改过的文件都有 `*.orig-<日期>` 备份，daily-report.sh 会列出并生成 diff；把 #109 的评论和这些 diff 交给笔记本上的 Claude 合并进套件。

## 实例被抢占回收

在控制台用相同的私网 IP 重建（A 再挂回辅助 IP，B 再挂回 eth1），更新笔记本 `~/.ssh/config` 里的公网 IP，对重建的那台重跑上面的 rsync 和 pem 拷贝，再给它贴当天那条提示词。重建的机器主机密钥变了，另外两台上要清掉它的旧指纹，否则 `ssh loadgen` 等别名会报 host key changed（以 A 为例）：

```sh
for h in ecs-B ecs-C; do ssh $h 'for ip in 172.30.106.138 172.30.106.139 172.30.106.140 172.30.106.141; do ssh-keygen -R $ip; done; rm -f ~/.ssh/cm-*'; done
```

（IP 换成 `plan.env` 里那台的地址。）重建的是 A 的话，还要重做上面第 5 步（装 `gh` 并登录），否则 R18 发不出评论。先在笔记本上跑
`test/perf/hosts/pull-results.sh --push` 把进度推回去，前提是**当天**拉过结果；本地只有前一天的结果时不要 `--push`，否则会把旧的 progress.md 推上去。同步任务一直在跑的话，当天的结果已经拉过，`--push` 可直接用。机器上 agent 的现场改动在 `~/freesbc-perf-results/kit/<角色>/`：**先把它们合并进本地仓库，再对那台机器做任何 rsync**，因为从本地仓库做的 `rsync --delete` 会把这些改动抹掉。soak 期间被回收：soak 要从头再跑，在报告里写明中断的那一次。
