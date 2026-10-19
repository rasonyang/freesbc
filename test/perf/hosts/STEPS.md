# 正式压测步骤参考（阿里云抢占式 ECS，issue #109）

> 这是各主机上 pi agent 的参考手册（`agents/*/AGENTS.md` 指向这里），不是操作员要读的文档。
> 操作员只看 [`RUNBOOK.md`](RUNBOOK.md)：把里面的提示词贴给三台主机上的 pi 即可。
> 测量项（M01 到 M08）及其命令、通过标准在 [`MEASURE.md`](MEASURE.md)；本文只负责装机（R00 到 R09）和收工（R18）。
> `ecs-user` 是登录用户（pi 也以它运行，自带免密 sudo）；pi 已装好，R07 无事可做。
> 本文是参考，不是必须逐字执行的脚本：某一步行不通时，agent 可以偏离、自行排障后重试，但必须把偏离（改了什么、为什么）记进 `/opt/freesbc/results/<role>/notes.md`；改过的文件先备份为 `<file>.orig-<日期>`。
> 笔记本侧的命令（R00 探测、R02 同步、`pull-results.sh`）由操作员或笔记本上的 Claude 执行；agent 不做。

目的：在三台实例上做 issue #109 要求的正式三机压测。2026-10-18 的结果在 [`docs/performance.md`](../../../docs/performance.md)，还没测的项目见其中的 [Pending](../../../docs/performance.md#pending)。
上一次是小规格的流程演练（已通过冒烟）；这次用大规格实例、两个 vSwitch，并且看性能。

进度保存在 loadgen 主机的 `/opt/freesbc/results/progress.md`（`test/perf/hosts/progress.sh show|next|set`）。装机和收工的步骤编号是
R00 到 R09、R18，测量是 M01 到 M08。每天收工时出报告并拉回笔记本（[收工](#收工)），第二天从第一个不是 `done` 的步骤继续（[第二天](#第二天)）。

脚本只做过 `bash -n`、shellcheck 和本地渲染后的 `freesbc check`；上次演练的冒烟在真实实例上跑通过，但这次新增的部分（eth1 在另一个 vSwitch、
`sbc-cores`、`hostmon`、`m03.sh`、`ladder.sh`、`m08.sh`）**没有在真实实例上跑过**，出问题时最先怀疑它们。
所有命令、文件名、日志字符串保持英文原样。

## 实例规格与拓扑

| 项 | A loadgen | B sbc（被测） | C switch |
|---|---|---|---|
| 规格 | 计算型，独享 vCPU（`ecs.c9i.2xlarge`，Intel Xeon 6982P-C；或 `ecs.c8a.2xlarge`，AMD EPYC 9T24，2026-10-18 正式压测用的是它），8 vCPU / 16 GiB，系统盘 40 GiB | Intel 1:2 计算型（`ecs.c9i.xlarge`，Intel Xeon 6982P-C），4 vCPU / 8 GiB，系统盘 40 GiB，**支持至少 2 块 ENI**，不设 `MemoryMax` | 计算型，独享 vCPU（`ecs.c9i.2xlarge`，Intel Xeon 6982P-C），8 vCPU / 16 GiB，系统盘 40 GiB |
| 可用区 | cn-wulanchabu-b | 同 | 同 |
| vSwitch / 网卡 | 公网 vSwitch `172.30.96.0/20`：eth0 主 IP + 两个辅助 IP（可选第三个 `A_LOADGEN2_IP`） | eth0 在公网 vSwitch；eth1（第二块 ENI）在**私网 vSwitch**，`B_PRIV_IP`；B 没有辅助 IP | 私网 vSwitch，eth0 `C_IP`；另有公网 IP（ssh、apt、docker、github 用，压测不使用） |
| 抢占式 | 是，含 soak | 是 | 是 |

B 和竞品的机器（Xeon X5670 6C/12T 2.93 GHz、8 GB、128 GB SSD、Debian 10、内核 4.19）比：核数少（2 核 4 线程 vs 6 核 12 线程），但每核快得多，总算力大致相当到略低；磁盘大小不是变量。
报告里要记录 B 的 `lscpu` 型号/主频，并写明 OS 差异：这里 Ubuntu 24.04（套件在它上面测过，Debian 10 已 EOL），竞品 Debian 10 / 4.19。

**两个 vSwitch 在同一可用区、同一个 VPC，VPC 在它们之间自动路由**：A（公网 vSwitch）能直接访问 C（私网 vSwitch）的私网 IP（ssh、sshfs、scp），不需要任何 OS 路由。
FreeSBC 的 `public.ip` 是 B 的 eth0 地址，`private.ip`（私网 SIP 固定在 `B_PRIV_IP:5060`）是 B 的 eth1 地址，eth1 和 C 同一个子网、直连，所以 B 上
不需要策略路由（`provision.sh` 只在两块网卡同子网时才加，那是 `PRIV_SUBNET_CIDR == SUBNET_CIDR` 的老布局）。eth1 不带默认路由。

安全组：**一个**安全组，组内全放行；公网只放 tcp 22，来源是管理员出口 CIDR。组内全放行等于演练时那张按角色收紧的表不再需要；
隔离靠 FreeSBC 的 socket 绑定和 C 上服务只接受 `B_PRIV_IP` 的配置（FreeSWITCH/Asterisk 无摘要认证，不能对别的地址放开）。

所有地址来自 [`plan.env`](plan.env)（唯一来源）。尚未创建的东西用 `__ASSIGN_IN_CONSOLE__` 占位，`provision.sh` 和 `render.sh` 遇到占位符会拒绝运行。

| 变量 | 含义 |
|---|---|
| `SUBNET_CIDR` / `PREFIX_LEN` | 公网 vSwitch 网段与前缀（172.30.96.0/20，20） |
| `PRIV_SUBNET_CIDR` / `PRIV_PREFIX_LEN` | 私网 vSwitch 网段与前缀（控制台新建后填，占位） |
| `A_IP`, `A_CARRIERGEN_IP`, `A_CARRIER_UAS_IP` | A 的主 IP；运营商发生器（`carrier_sources`）；运营商 UAS（carrier-out） |
| `A_LOADGEN2_IP` | 可选：A 的第三个辅助 IP，M06 的第二个客户端源地址（空 = 没有） |
| `B_PUB_IP` | B eth0 的 IP，`public.ip` = `public.bind` |
| `B_PRIV_IP` / `B_PRIV_IF` / `B_PRIV_ADDR_MODE` | B 第二块 ENI 的 IP（占位）/ 网卡名（eth1）/ `static` 或 `dhcp` |
| `B_GOMEMLIMIT` / `B_MEMORY_MAX` | B 上 FreeSBC 的 `GOMEMLIMIT`（默认 6GiB）/ systemd `MemoryMax`（空 = 不限，B 本身 8 GiB） |
| `C_IP` | C 的主 IP（私网 vSwitch，占位） |
| `NET_IF` / `A_EXTRA_IF` | 主网卡名；放 A 额外 IP 的网卡（都是 eth0） |
| `DOCKER_REGISTRY_MIRROR` | C 的 Docker 镜像加速器 URL（空 = 不用，见 R05） |

C 上的端口：SIPp UAS `5060`（carrier-out 的 UAC 从 `5070` 发出）、Asterisk `5080`（RTP `10000-10999`）、
FreeSWITCH `5090`（RTP `20000-59999`）、SIPp RTP echo `6000+`。同一时间只有一个后端被用，由 B 上的配置决定（`freesbc-use sipp|fs|ast`）。

调优（`provision.sh` 做）：所有主机 `rmem_max`/`wmem_max` 8 MiB、`netdev_max_backlog`、`udp_mem`、`nofile`/`nproc` 不限；B 和 C 的临时端口范围移到
60000-65535（避开 RTP 范围）；B（4 vCPU）：`rtp: 10000-59999`、`max_sessions: 25000`（按预期并发留足余量，上限不是瓶颈；核数相关的只有 `sbc-cores`）、`LimitNOFILE=1048576`、`GOMEMLIMIT=$B_GOMEMLIMIT`（B_MEMORY_MAX 为空则无 `MemoryMax`）、
`sbc-cores`（限核）和 `hostmon`（整机采样）装到 `/usr/local/bin`；C：FreeSWITCH `sessions-per-second` 5000、`max-sessions` 30000、RTP 20000-59999、日志 warning。

用户：登录用 `ecs-user`（有免密 sudo，没有 root 登录），run.sh、主机间 ssh、pi agent 都用它。这是一次性实例上的有意取舍，不要照搬到真实主机。

预计 provision 耗时（估算）：loadgen 8 到 12 分钟，sbc 5 到 8 分钟，switch 10 到 20 分钟。三台可并行。

出网（上次演练的探测结果，这次以 R00 为准）：Docker Hub 和 proxy.golang.org 不通；goproxy.cn、golang.google.cn、mirrors.cloud.aliyuncs.com（apt）、api.deepseek.com、npm 可达；
**github.com 从 C 可达**（上次演练实测），所以 C 上的 SIPp 源码包直接下载；A 下载后 `scp` 到 C 只是备选（`provision.sh fetch-sipp`）。

## 笔记本 ssh 配置

**先做这一步**：`ssh -G ecs-A | grep -i '^hostname'` 必须是 A 的公网 IP，`ecs-B` 是 B 的，`ecs-C` 是 C 的。别名指错主机时跑某个角色的 provision 会把那台机器配错。
笔记本的 `~/.ssh/config`（公网 IP 只写在笔记本上，不进仓库）：

```
Host ecs-A
  HostName <A 的公网 IP>
Host ecs-B
  HostName <B 的公网 IP>
Host ecs-C
  HostName <C 的公网 IP>
Host ecs-A ecs-B ecs-C
  User ecs-user
  IdentityFile ~/.ssh/aicc-dev-ecs.pem
  IdentitiesOnly yes
  StrictHostKeyChecking accept-new
```

实例重建后公网 IP 会变，改这里即可。下文所有 `ecs-A`、`ecs-B`、`ecs-C` 都指这三个别名。
**主机之间的别名 `loadgen`、`sbc`、`switch` 在 `provision.sh` 跑过之前并不存在**：那之前主机间（包括 agent）用
`ssh -i ~/.ssh/aicc-dev-ecs.pem ecs-user@<plan.env 里的 IP>`。另外，`~/.ssh/aicc-dev-ecs.pem.pub` 如果存在但和 pem 不是一对（上次演练遇到过），
OpenSSH 会先提供这把错的公钥而登录失败：`provision.sh` 的自检会 FAIL 并指出办法（把 `.pub` 改名为 `.pub.stale`）。

## R00 环境检查

实例的情况可能和计划不同（换规格、可用区没有某个型号）。先跑只读探测，**它不改任何东西**：

```sh
for h in ecs-A ecs-B ecs-C; do ssh $h 'bash -s' < test/perf/hosts/probe.sh > /tmp/probe-$h.txt 2>&1; done
less /tmp/probe-ecs-A.txt
```

对照输出填 `plan.env`（在笔记本的仓库里改，R02 再同步到三台主机）：

1. **前缀和网段**：公网 vSwitch 的 `vswitch-cidr-block` 填 `SUBNET_CIDR`，`netmask` 对应的位数填 `PREFIX_LEN`；B 的 eth1 那一行元数据（`mac …: primary=… vswitch=…`）给出私网 vSwitch 的 CIDR 和 B 的私网地址：
   填 `PRIV_SUBNET_CIDR`、`PRIV_PREFIX_LEN`、`B_PRIV_IP`；C 的 `primary=` 填 `C_IP`（必须落在 `PRIV_SUBNET_CIDR` 里，`provision.sh` 会检查）。
2. **网卡名**：A、C 带主 IP 的网卡填 `NET_IF`（预期 eth0）；B 的第二块 ENI 在 OS 里的名字填 `B_PRIV_IF`（预期 eth1；热挂载的 ENI 在 OS 里没有配置，`ip -br addr` 里是 DOWN、没有地址，这是正常的，`provision.sh sbc` 会配）。
3. **B 应当有两块 ENI**（元数据两行）：eth0 在公网 vSwitch，eth1 在私网 vSwitch。只有一行说明第二块 ENI 没挂上，回 R01。
   若私网和公网碰巧是同一个 vSwitch（`PRIV_SUBNET_CIDR == SUBNET_CIDR`，老布局），`provision.sh sbc` 改走源地址策略路由 + `rp_filter=2` 的路径；正常情况下是两个 vSwitch，不走它。
4. **C 的出网**：C 在私网 vSwitch，没有公网 IP 就没有出网。预期 C 有公网 IP；探测输出的出网表会证实（apt 镜像、goproxy.cn、github.com 应可达，Docker Hub 不可达）。
5. 看探测输出里的几件事：`sudo=ok`（否则 provision 跑不了）、`ufw` 应为 inactive、`instance/instance-type`、`nproc`、内存（B 8 GiB）、`lscpu` 型号。

另外，如果某台上有多余的网卡（上次演练 A 有个 DOWN 的 eth1），`provision.sh` 的自检要求"只有一条默认路由，未使用的 eth1 是 DOWN 或没有默认路由"；A 的 eth1 若存在，保持 `sudo ip link set eth1 down`。

角色自检（防止别名指错）：`ssh ecs-A hostname -I` 必须包含 `A_IP`，`ecs-B` 包含 `B_PUB_IP`，`ecs-C` 包含 `C_IP`；`provision.sh` 也会在改动任何东西之前拒绝在不持有本角色主 IP 的主机上运行。

完成检查：三份 `/tmp/probe-*.txt` 看过，`plan.env` 里 `SUBNET_CIDR`、`PREFIX_LEN`、`PRIV_*`、`NET_IF`、`B_PRIV_IF`、`B_PRIV_IP`、`C_IP` 与实际一致。
标记：`R00` 在 R06 后统一标（progress.md 此时还不存在）。

## R01 控制台：私网 vSwitch、B 的第二块 ENI、安全组

按顺序（可用区都是 cn-wulanchabu-b，同一个 VPC）：

1. **新建私网 vSwitch**：专有网络控制台 → 交换机 → 创建，选和公网 vSwitch 同一个可用区，CIDR 自选且不与 `172.30.96.0/20` 重叠（例如 `172.30.112.0/24`）。把 CIDR 和前缀写进 `plan.env` 的 `PRIV_SUBNET_CIDR`、`PRIV_PREFIX_LEN`。
2. **创建 C**：按上面的规格，网络选私网 vSwitch，分配公网 IP（ssh、apt、docker、github 用）。启动后 `C_IP` = 它的主私网 IP，写进 `plan.env`。
3. **创建 B**：Intel 1:2 计算型（`ecs.c9i.xlarge`，4 vCPU / 8 GiB），系统盘 40 GiB，主网卡在公网 vSwitch；规格必须支持至少 2 块 ENI（创建前在规格详情里确认网卡数）。**不要给 B 分配辅助私网 IP。** 不设内存上限。
4. **创建 B 的第二块 ENI**：ECS 控制台 → 网络与安全 → 弹性网卡 → 创建，选私网 vSwitch、同一个安全组；挂载到 B（热挂载即可）。这块 ENI 的主私网 IP 写进 `plan.env` 的 `B_PRIV_IP`（`B_PRIV_IF` 以 R00 看到的名字为准）。
   如果实例规格不支持第二块 ENI 或配额不够，换规格；没有它就没有两个平面。
5. **创建 A**：公网 vSwitch，主 IP 写进 `A_IP`；在**主网卡**上"管理辅助私网 IP"，分配两个（`A_CARRIERGEN_IP`、`A_CARRIER_UAS_IP`），需要 M06 的第二个客户端源地址时再加第三个（`A_LOADGEN2_IP`）。辅助 IP 的配额是"每块 ENI 的私网 IP 数"，A 需要 ≥ 3（或 4）。
   A 的 IP 不要用已被占用的地址。
6. **安全组**：三台和 B 的 ENI 用**同一个**安全组；入方向：组内全放行（来源是本安全组），再加一条 tcp 22 来自管理员出口 CIDR。不要对公网开放别的端口。
7. 操作系统里的配置不是控制台做的：`provision.sh` 用 netplan 配 A 的辅助 IP 和 B 的 eth1（前缀来自 `plan.env`）。

完成检查：`grep ASSIGN test/perf/hosts/plan.env` 无输出（`DOCKER_REGISTRY_MIRROR` 和可选键除外，它们不是占位符）；三台能从笔记本 ssh；`ssh ecs-B 'ip -br link'` 能看到 eth1。

### C 的出网

C 有公网 IP，和 A、B 一样直接出网，正常情况下**不需要做任何出网配置**。Docker Hub 仍然不通：FreeSWITCH 镜像走 `DOCKER_REGISTRY_MIRROR`（R05）。
C 没有公网 IP（或出方向被限）时才看附录；注意附录里的"经 A 做 NAT"方案现在跨 vSwitch，基本不可行，优先给 C 一个公网 IP。

## R02 把仓库同步到三台主机

在笔记本的仓库根目录，用要演练的提交。`/opt/freesbc` 必须是这个路径（`REMOTE_PERF=/opt/freesbc/test/perf`），
先让 `ecs-user` 拥有它，这样 rsync 不需要 sudo（`provision.sh` 之后保持它归 `ecs-user`，整个 `/opt/freesbc` 都归 `ecs-user`）：

```sh
git rev-parse --short HEAD > /tmp/COMMIT
for h in ecs-A ecs-B ecs-C; do
  ssh $h 'sudo install -d -o ecs-user -g ecs-user /opt/freesbc'
  rsync -az --delete --exclude .git --exclude test/perf/out --exclude results ./ $h:/opt/freesbc/
  rsync -a /tmp/COMMIT $h:/opt/freesbc/COMMIT
done
```

`plan.env` 改动后重新同步即可。完成检查：`ssh ecs-A ls /opt/freesbc/test/perf/hosts/provision.sh`，且三台上
`grep ASSIGN /opt/freesbc/test/perf/hosts/plan.env` 无输出。

## R03 到 R05 Provision

三个终端并行（也可以先做 A，因为后面的步骤从 A 驱动）。每次运行都以自检结束，逐项 `PASS`/`FAIL`，有 FAIL 就退出 1：

```sh
ssh ecs-A 'sudo /opt/freesbc/test/perf/hosts/provision.sh loadgen'
ssh ecs-B 'sudo /opt/freesbc/test/perf/hosts/provision.sh sbc'
ssh ecs-C 'sudo /opt/freesbc/test/perf/hosts/provision.sh switch'
```

**R05 之前给 C 准备 FreeSWITCH 镜像**（Docker Hub 在国内机器上不通，C 也一样；R00 探测确认）。`provision.sh switch` 的做法（上次演练在 C 上验证过）：

1. `docker.io` 从 apt（阿里云镜像）安装。
2. 如果 `plan.env` 里设了 `DOCKER_REGISTRY_MIRROR`，写 `/etc/docker/daemon.json`：`{"registry-mirrors":["<URL>"]}` 并重启 docker（只在内容变了时）。
   这个 URL 是你自己阿里云账号的镜像加速器：控制台 **容器镜像服务 → 镜像加速器**。没设就不碰 `daemon.json`。
3. 通过它拉 `FS_IMAGE`（默认 `safarov/freeswitch:latest`；上次演练拉到的是 FreeSWITCH 1.10.0）。DaoCloud 不再作为默认（`rasonyang/freeswitch` 经 `docker.m.daocloud.io` 返回 403/not found，该域名从 B 还会 502）。
   想用别的镜像：`FS_IMAGE=<repo:tag> sudo -E provision.sh switch`，或 `FS_IMAGE_PULL=<ref>`（拉这个再打标签成 `FS_IMAGE`）。镜像里要有 `/usr/bin/freeswitch` 和 `/usr/share/freeswitch/conf/vanilla`。
4. 备用（tar）：本地已有镜像，或 `/var/tmp/freeswitch-image.tar.gz`（`FS_IMAGE_TAR`）存在时优先用它，不联网。在笔记本上生成：

```sh
docker pull --platform linux/amd64 safarov/freeswitch:latest      # 必须是 amd64；Apple Silicon 一定要带 --platform
docker save safarov/freeswitch:latest | gzip > /tmp/freeswitch-image.tar.gz
scp /tmp/freeswitch-image.tar.gz ecs-C:/var/tmp/
```

没有镜像、`DOCKER_REGISTRY_MIRROR` 为空、Docker Hub 又不通时 `provision.sh` **立即报错退出**并说明原因，不会卡住。
**实际的 FreeSWITCH 版本**会在 provision 日志、自检的 `INFO` 行、`/etc/perf-kit/freeswitch-version` 里给出，并进 `daily-report.sh` 的主机表和 summary：报告里要写出来（版本不是 1.10.12 时说明）。

SIPp 源码包：**C 能访问 github.com**（上次演练实测），`provision.sh switch` 直接下载并校验 sha256（写死在 provision.sh 里）。下载失败时会退回 Ubuntu 的 sip-tester（版本不同，自检的 pcap/rtp_echo 项可能 FAIL）。
备选：在 A 上 `sudo /opt/freesbc/test/perf/hosts/provision.sh fetch-sipp`，然后 `scp /var/tmp/sipp-3.6.1.tar.gz switch:/var/tmp/`（装好别名前用 `ssh -i ~/.ssh/aicc-dev-ecs.pem`，目标是 `C_IP`），再重跑 `provision.sh switch`（它优先用 `/var/tmp/` 里的包）。

自检全 PASS 才算完成（`ssh to <host>` 各项用 `~/.ssh/aicc-dev-ecs.pem`；某台主机还没装好或没有 pem 时这些项 FAIL 是正常的）。三个脚本都是幂等的：失败后直接重跑。
自检还会检查：`~/.ssh/aicc-dev-ecs.pem.pub`（若存在）是否和 pem 是一对——不是就 FAIL，并给出办法：`mv ~/.ssh/aicc-dev-ecs.pem.pub ~/.ssh/aicc-dev-ecs.pem.pub.stale`。

它们做的事（读失败信息时用）：sysctl（`rmem_max`/`wmem_max` 8388608、`netdev_max_backlog`、`udp_mem`、B/C 的临时端口范围 60000-65535）；`nofile` 1048576、`nproc` 不限；`ecs-user` 的 ssh 配置（检查 `~/.ssh/aicc-dev-ecs.pem` 存在、权限 600、.pub 不陈旧）；
`/etc/perf-kit/` 里按 `plan.env` 渲染的 FreeSBC 配置与 ssh 配置；A：netplan 辅助 IP（`/etc/netplan/61-perf-*.yaml`，前缀取 `PREFIX_LEN`）、SIPp 3.6.1（带 pcap；失败退回 `sip-tester`）、Go（版本取自 `go.mod`）、`/usr/local/bin/webrtcload`、`results/progress.md`；
B：eth1（`/etc/netplan/62-perf-b-priv.yaml`，`B_PRIV_IP/PRIV_PREFIX_LEN` 静态或 DHCP，不带默认路由，没有策略路由）、Go、`/usr/local/bin/freesbc`、自签证书、`freesbc.service`（`LimitNOFILE=1048576`、`GOMEMLIMIT=$B_GOMEMLIMIT`、可选 `MemoryMax=$B_MEMORY_MAX`）、
`/usr/local/bin/freesbc-use`、`sbc-cores`、`hostmon`、对三份渲染配置的 `freesbc check`，自检里还会从 B_PRIV_IP ping C_IP；
C：SIPp、docker.io、FreeSWITCH 容器 `freeswitch-perf`（stock vanilla 配置，去掉 stock profile，装入仓库的 `perf` profile 和 `perfload` dialplan，IP 换成 `C_IP`，`sessions-per-second` 5000、`max-sessions` 30000、RTP 20000-59999、日志 warning；`--ulimit nofile`/`nproc` 不限）、
Asterisk（Ubuntu 包，pjsip 在 `:5080`，endpoint `perf` 按 IP `B_PRIV_IP` 识别，`u`/`w` 各 200 个用户，禁用 `chan_sip` 以保证 `5060` 空闲）、`/usr/local/bin/fs_cli`（`docker exec` 包装，要用 `sudo`）。
不启用主机防火墙：安全组就是防火墙。

完成后标记（A 上 progress.md 已创建）：

```sh
ssh ecs-A "cd /opt/freesbc && for s in R00 R01 R02 R03 R04 R05; do test/perf/hosts/progress.sh set \$s done provisioned; done"
```

（只在对应步骤真的做完时这样标；有哪步没做就单独标。）

## R06 主机间 ssh

三台主机都有 `~/.ssh/aicc-dev-ecs.pem`（权限 600，不用交换公钥），`provision.sh` 在每个角色上把渲染出的 ssh 配置装到 `ecs-user` 的 `~/.ssh/config`，别名 `loadgen`、`sbc`、`switch` 在任意一台上都能用（地址取自 `plan.env`，用户 `ecs-user`，`IdentityFile ~/.ssh/aicc-dev-ecs.pem`，`StrictHostKeyChecking accept-new`，开连接复用因为采样器每 2 秒开一次 ssh）。pem 缺失时 `provision.sh` 会明确报告，由操作员补。`provision.sh authkey` 仅作备用。完成检查（在任意一台上）：

```bash
ssh sbc hostname && ssh switch hostname && ssh loadgen hostname
```

## R07 pi agent

已在三台主机上装好并配好（DeepSeek），无事可做；直接 `progress.sh set R07 done`。`provision.sh pi` 子命令仍在，但不需要。

## R08 到 R17 的通用准备

> 正式压测只需要 R08、R09 两个冒烟；R10 到 R17 是上次演练的场景流程，现在由 [`MEASURE.md`](MEASURE.md) 取代，保留作参考，不必做。

下面所有运行命令都在 A 上，以 `ecs-user` 身份，在 `/opt/freesbc` 目录：

```sh
cd /opt/freesbc
. test/perf/hosts/env.sh sipp      # 或 fs、ast：设置 TOPOLOGY=hosts、各 IP（取自 plan.env）、SBC_EXEC、SWITCH_EXEC
ssh sbc freesbc-use sipp           # B 必须跑对应的配置
```

`env.sh fs|ast` 设 `SWITCH=freeswitch`，对 `run.sh` 只意味着“不启动 SIPp UAS，并拒绝运营商场景”；真正的后端由 `freesbc-use` 选的配置决定。
输出在 `test/perf/out/<stamp>-<scenario>/`。每个场景不超过约 5 分钟。每步做完记录：
`test/perf/hosts/progress.sh set R08 done "5/5 calls"`（失败用 `failed "原因"`）。

## R08 冒烟：SIPp 后端

```sh
. test/perf/hosts/env.sh sipp && ssh sbc freesbc-use sipp
test/perf/run.sh -r 1 -t 5 -H 5 -u 5 call
```

完成检查（`test/perf/hosts/runcheck.sh test/perf/out/<run>` 必须无 FAIL：SIPp 被中止、`calls_ok + calls_failed < calls_created` 时 run.sh 仍显示 0% 失败，但那是失败）：汇总里 `calls_created=5 calls_ok=5 calls_failed=0`、`active_registrations_peak=5`、`media_ports_in_use_peak` 大于 0 且结束时 `end=0`、
`invite_rejects=0 admission_drops=0 udp_rcvbuf_errors=0`。若出现 `WARNING: cannot scrape FreeSBC metrics`：`ssh sbc sudo /opt/freesbc/test/perf/sample.sh | head`。

## R09 冒烟：FreeSWITCH

```sh
. test/perf/hosts/env.sh fs && ssh sbc freesbc-use fs
ssh switch 'sudo fs_cli -x "sofia profile perf flush_inbound_reg"'
test/perf/run.sh -r 1 -t 5 -H 5 -u 5 call
# FreeSWITCH 1.10 prints no Reg-User field here (it is "User:"); count rows of show registrations instead
ssh switch 'sudo fs_cli -x "show registrations"' | grep -c '@'
```

完成检查：`runcheck.sh` 无 FAIL（0 个失败呼叫，也没有被中止的 SIPp，`calls_ok` 等于 `calls_created`），最后一条命令输出 5（FreeSWITCH 盲注册接受的 5 个用户）。

## R10 Asterisk：手动 REGISTER 与回声呼叫

`SWITCH=freeswitch run.sh`（`env.sh ast` 所设）对 Asterisk 不需要改动，所以 R11 才是真正的测试；这里先手动证明。
Asterisk 对 `u000001`..`u000200` 和 `w000001`..`w000200` 的 REGISTER 不要摘要认证：唯一的 endpoint `perf` 按 FreeSBC 的私网 IP（`B_PRIV_IP`）识别，
并把所有这些 aor 列在自己名下；context `perfload` 的 `2000` 分机执行 `Answer()` 和 `Echo()`。其他 IP 来的请求不会被识别（安全组也挡了）。

```sh
ssh sbc freesbc-use ast
cd /opt/freesbc/test/perf
printf 'SEQUENTIAL\nu000001\n' > /tmp/u1.csv
# 1. REGISTER，必须用呼叫将使用的同一个 IP:port（FreeSBC 只放行来自活跃注册源地址的 INVITE）
sipp -sf sipp/register.xml -i $LOADGEN_IP -p 5070 -inf /tmp/u1.csv -key expires 3600 \
     -m 1 -r 1 -cid_str '%u@%s' -nostdin -recv_timeout 10000 $SBC_PUBLIC:5060
ssh switch 'sudo asterisk -rx "pjsip show contacts"' | grep u000001
# 2. 回声呼叫 8 秒：SIPp 播放 pcap，Asterisk 回声
sipp -sf sipp/uac_call.xml -i $LOADGEN_IP -p 5070 -inf /tmp/u1.csv -s 2000 -d 8000 \
     -m 1 -r 1 -key pcap /opt/freesbc/test/perf/pcap/g711u_10s.pcap -nostdin -recv_timeout 10000 $SBC_PUBLIC:5060 &
sleep 4; ssh switch 'sudo asterisk -rx "core show channels"'; wait
ssh sbc 'curl -s -u admin:perf localhost:8081/metrics' | grep -E '^freesbc_rtp_packets_(rx|tx)_total'
```

完成检查：第 1 步 SIPp 打印 `Successful call 1`，contacts 里有带 contact 的 `u000001`；第 2 步 `Successful call 1`，
`core show channels` 看到一个处于 `Echo` 的 `PJSIP/perf-...` 通道，FreeSBC 的 rx 和 tx RTP 计数都非零（某些构建只在会话结束后才计数）。

## R11 通过 run.sh 测 Asterisk

```sh
. test/perf/hosts/env.sh ast && ssh sbc freesbc-use ast
test/perf/run.sh -r 1 -t 5 -H 5 -u 5 call
ssh switch 'sudo asterisk -rx "pjsip show contacts"' | grep -c 'u00000[1-5]'
```

完成检查：`calls_failed=0`，5 个 contact。“run.sh 能不能对 Asterisk 用”：能，`register`、`call`、`webrtc`（有 `w` 用户）无需改 harness，只要 `-u` 不超过 200
（要更多就调大 `ASTERISK_USERS` 并重跑 `provision.sh switch`，上限 500）；运营商场景不行（和 FreeSWITCH 一样）。
Asterisk 是否真会这样应答盲 REGISTER 还没验证（未验证）：R10 第 1 步若收到 401/403/404，看 `ssh switch 'sudo asterisk -rx "pjsip show endpoint perf"'`，并在重发 REGISTER 时 `sudo asterisk -rvvv`。

## R12 场景 register（SIPp 后端）

```sh
. test/perf/hosts/env.sh sipp && ssh sbc freesbc-use sipp
test/perf/run.sh -r 20 -t 5 -u 100 register
```

完成检查：`runcheck.sh` 无 FAIL（`calls_failed=0` 且 `calls_ok` 等于 `calls_created`），`active_registrations_peak=100`。

## R13 场景 call（SIPp 后端）

```sh
test/perf/run.sh -r 5 -t 20 -H 10 -u 100 call
```

100 个呼叫，约 50 并发。完成检查：`calls_failed=0`，有 plateau 块，`plateau_tx_over_rx` 接近 1.0，结束时 `ports_in_use` 回到 0，`udp_rcvbuf_errors=0`。
hold 为 10 秒，`run.sh` 会用 `python3` 生成 pcap（已安装）。

## R14 场景 carrier-in（SIPp 后端）

```sh
test/perf/run.sh -r 5 -t 20 -H 10 carrier-in
```

发生器在 A 上，从 `A_CARRIERGEN_IP` 发出（在 `carrier_sources` 里）。完成检查：`calls_failed=0`。

## R15 场景 carrier-out（SIPp 后端）

switch 侧的 UAC 跑在 C 上，运营商 UAS 在 A 上（`A_CARRIER_UAS_IP`，由 `run.sh` 本地启动，因为 `CARRIER_EXEC` 为空）。
`run.sh` 给每个角色同一个 `$REMOTE_PERF/out/<run>` 路径，所以 C 必须能看到 A 的 `out` 目录，否则 C 上的 SIPp 写不了统计文件，汇总里就没有 SIPp 部分
（见 [hosts 模式说明](#hosts-模式说明)）。用 sshfs 挂载（未验证）：

```sh
ssh switch 'mountpoint -q /opt/freesbc/test/perf/out || sshfs -o cache=no,reconnect loadgen:/opt/freesbc/test/perf/out /opt/freesbc/test/perf/out'
test/perf/run.sh -r 5 -t 20 -H 10 carrier-out
ssh switch 'fusermount3 -u /opt/freesbc/test/perf/out'
```

完成检查：SIPp 的 `main` 部分 `calls_failed=0`，`freesbc_edge_invite_rejects_total` 仍为 0。`-H` 取 8 或更小可避开生成 pcap 的路径。
不用 sshfs 时，可以手动检查：在 A 上跑运营商 UAS，在 C 上跑 `switch_uac_carrier.xml` 并加 `-stf /tmp/x.csv`，用法见该文件头部。

## R16 场景 webrtc（FreeSWITCH）

```sh
. test/perf/hosts/env.sh fs && ssh sbc freesbc-use fs
test/perf/run.sh -r 2 -t 10 -H 10 -u 30 webrtc
test/perf/run.sh -r 1 -t 3 -H 8 -u 10 -w wss://$SBC_PUBLIC:443 webrtc     # TLS 变体
```

先 20 个呼叫，再 3 个。完成检查：`RESULT` 行里 `calls_failed=0`、`rtp_echoed` 接近 `rtp_sent`、`reg_failed=0`。
ICE 候选来自 A 的几个地址（`A_IP` 和两个辅助 IP；A 的额外地址都在主网卡 eth0 上，eth1 不用）；offer 的 `c=` 取第一个，FreeSBC 靠 ICE 检查锁定（多地址下未验证）。

## R17 指标与 pprof

在一个短负载运行期间（负载放后台，抓 10 秒 profile）：

```sh
d=/opt/freesbc/results/$(date +%F); mkdir -p $d/pprof
(test/perf/run.sh -r 5 -t 30 -H 10 -u 100 call > /tmp/r17.txt 2>&1 &)
sleep 15
ssh sbc "curl -s -u admin:perf -o /tmp/cpu.pb.gz 'localhost:8081/debug/pprof/profile?seconds=10'"
scp -q sbc:/tmp/cpu.pb.gz $d/pprof/cpu.pb.gz
ssh sbc "curl -s -u admin:perf 'localhost:8081/debug/pprof/goroutine?debug=1'" | head -40 > $d/pprof/goroutine.txt
sleep 30; tail -5 /tmp/r17.txt
```

完成检查：`$d/pprof/cpu.pb.gz` 非空；最新的 `test/perf/out/*/metrics.csv` 里 `cpu_s`、`rss_bytes`、`open_fds`、`goroutines` 列不为空（`awk -F, 'NR==2' ...`）；
`daily-report.sh`（收工）会把对应的二进制放在 profile 旁边，拉回笔记本后 `go tool pprof -top freesbc-linux cpu.pb.gz` 就能用。

## 收工

R18。在 A 上以 `ecs-user` 身份，笔记和进度都已更新：

0. 先判每个 run：`test/perf/hosts/runcheck.sh`（FAIL 的 run 不能当结果引用；SIPp 被中止、`calls_ok + calls_failed < calls_created` 也是 FAIL）。`daily-report.sh` 会把同样的判定写进 summary.md。
1. 出报告：`cd /opt/freesbc && test/perf/hosts/daily-report.sh`。它把运行输出、`metrics.csv`、pprof、各角色的 `notes.md`、裁剪过的 FreeSBC / FreeSWITCH / Asterisk 日志和主机/版本表
   收进 `/opt/freesbc/results/<date>/` 和 `<date>.tar.gz`，其中所有**公网 IPv4**（私网地址保留）以及密钥/口令内容都被抹掉，并写出 `summary.md`——可直接贴成 issue 评论。贴出去之前自己读一遍。
   summary.md 在 M03 run 存在时带一张与竞品的对照表（`m03-table.sh`），并附 `measure-results.md` 的前 60 行。
2. 发评论（在 A 上，`gh` 由操作员按 RUNBOOK「笔记本上做」第 5 步装好并登录；`gh auth status` 未登录时不要自己登录，告诉操作员）：先读一遍 `summary.md`，并 `grep -nE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|password|BEGIN|key' summary.md` 确认没有公网 IP（`172.30.*` 私网地址可以）、密钥或口令，然后
   `gh issue comment 109 --repo rasonyang/freesbc --body-file /opt/freesbc/results/<date>/summary.md`。这是 `gh` 在 A 上唯一允许的写操作（soak 结束后再发一条 soak 报告）。
   可选备份：在笔记本上 `test/perf/hosts/pull-results.sh`（默认 `-H ecs-A`，目录 `~/freesbc-perf-results/`，可用 `-d` 改；拒绝仓库内的目录）。
3. 可选，省第二天的 provision 时间：给每台实例做自定义镜像（ECS 控制台 → 实例 → 更多 → 创建自定义镜像，无需停机）。镜像里的主机上 `provision.sh` 仍然可以安全重跑
   （每一步先检查再动手；会重建 `freesbc` 和 `webrtcload`、重建 FreeSWITCH 容器、重新生成 Asterisk 用户和渲染配置）。做镜像前删掉 pi 密钥
   （`rm ~/.pi-env`，pi 的密钥文件，做完镜像要重新配），否则镜像会带着它；镜像会占一点存储费用。
4. 标记 R18：`test/perf/hosts/progress.sh set R18 done "report posted"`，**然后再运行一次 `test/perf/hosts/daily-report.sh --retar`**（只重新打包 `<date>.tar.gz`，带上最终的 progress.md 和 summary.md；上次演练的压缩包早于 R18 的标记）。再在笔记本上 `pull-results.sh --all` 拉回（B、C 只拉各自的角色子目录，不会覆盖 A 的文件）。
5. 释放：释放三台抢占式实例前，辅助私网 IP 随主网卡一起释放；第二天重新创建后把私网 vSwitch 的 CIDR、B 的 eth1 地址和 C 的地址回填 `plan.env`（可能不同）。

## 第二天

1. 按同样的私网 IP 重建三台实例（从镜像或全新的 Ubuntu 24.04）。重新给 A 分配辅助私网 IP，给 B 重新挂第二块 ENI（私网 vSwitch），把新值写进 `plan.env`（R01），更新笔记本 `~/.ssh/config` 里的公网 IP，
   重新跑 R00 的探测（网卡名、前缀、B 的 eth1）。
2. 从镜像来的：先 R02 同步仓库（`plan.env` 变了就必须同步），再各主机 `ssh rh-X 'sudo /opt/freesbc/test/perf/hosts/provision.sh <role>'`（几分钟）。全新的：R02，再 R03 到 R06；若 C 没有公网 IP，附录里的出网也要重做。
3. 把进度和结果推回 A（`-u`，不覆盖更新的文件）：`test/perf/hosts/pull-results.sh --push`，或手动
   `rsync -auz ~/freesbc-perf-results/ ecs-A:/opt/freesbc/results/`。
4. 验证：三台各 `sudo provision.sh check`，在 A 上 `ssh sbc hostname && ssh switch hostname`。
5. 继续：A 上 `/opt/freesbc/test/perf/hosts/progress.sh next` 给出第一个不是 `done` 的步骤，从那里往下做。

## 抢占式实例被回收

1. 记下被打断的步骤和时间。A 还在的话：`test/perf/hosts/progress.sh set R<nn> failed "spot reclaimed"`。如果被回收的是 A，先重建 A、推回进度（第二天第 3 步），再标记。
2. 只重建那一台，用同样的主私网 IP，重新分配辅助私网 IP（可能换了，改 `plan.env` 并 R02 同步到所有主机），跑它的 `provision.sh <role>`；
   A 或 C 全新重建的话，R06 密钥要重做（它们的 ecs-user 密钥变了）。
3. 新主机上 `provision.sh check`，然后重试被打断的步骤。被中止的运行留下的 `out/` 目录保留即可，报告里忽略它们（`summary.md` 按目录列出运行）。

## hosts 模式说明

读 `run.sh` 得到的结论（没有在真实主机上跑过）：

* 从 `/opt/freesbc` 运行 `run.sh`（或者和 `REMOTE_PERF` 同一路径）：它把 `users.csv`、生成的 pcap 和 `-n` 场景副本写在自己的 `out/` 下，
  却把 `$REMOTE_PERF/out/...` 交给 SIPp 进程，两者只有在 checkout 就在 `REMOTE_PERF` 时才一致。本地的 SIPp 角色（客户端/运营商发生器、运营商 UAS）因此可用。
* 通过 `*_EXEC` 跑在别的主机上的 SIPp 角色（这里是 C 上的 carrier-out UAC）看不到 `$REMOTE_PERF/out/<run>`：它的 `-stf` 统计文件、`-n` 去掉媒体的场景、生成的 pcap（`-H` 大于 8）都在那里，
  而汇总只从本地 `out/` 读 SIPp 统计。R15 用 sshfs 解决。SIPp 后端的 `call`、`register`、`carrier-in` 和 UAS 本身不受影响（UAS 只需要 `$REMOTE_PERF/sipp/`）。
* `sample.sh` 经 `ssh sbc sudo` 运行：要 sudo 才能数别的用户进程的 fd（`/proc/<pid>/fd`）；`ADMIN_URL/USER/PASS` 的默认值和配置一致。采样器每 2 秒一次 ssh，必须有连接复用（`ssh_config` 已配）。
* README 里“hosts 模式没有在本仓库的测试中跑过”的说法依然成立，这次演练是第一次实际运行。

## pi 使用说明

[pi](https://pi.dev) 是终端里的编码 agent（npm 包 `@earendil-works/pi-coding-agent`，命令 `pi`，需要 Node 22.19 或更新）。演练可以每台主机开一个 pi 会话，
模型用 DeepSeek 的 `deepseek-flash`。下面的事实来自 2026-10-17 读到的 pi 文档，未验证的已标注。

* 安装：三台主机上已装好并配好，不需要（可选的 `provision.sh pi` 仍在）。它从 NodeSource 装 Node 22.x（Ubuntu 24.04 自带的 Node 太旧），
  再 `npm install -g --ignore-scripts @earendil-works/pi-coding-agent`（`NPM_REGISTRY` 可换源），并写 `~/.pi/agent/models.json` 作为兜底，
  以防 pi 内置模型目录里没有 `deepseek-flash`（未验证）。如果它和内置 `deepseek` provider 冲突，把文件里的 provider 名改成 `deepseek-custom`，并用 `--provider deepseek-custom`。
* 网络：pi 要访问 `api.deepseek.com`。A、B 直连可达（401）；C 现在有公网 IP，应该同样可达，R00 的探测和 `provision.sh check` 里的 `pi: api.deepseek.com reachable` 会确认，所以 pi 可以装在三台主机上。若某台主机没有公网 IP，见附录（经代理时 pi 是否可用未验证）。
* 密钥：DeepSeek 从环境变量 `DEEPSEEK_API_KEY` 读取。绝不能写进仓库或脚本。`sudo pi-set-key`（提示输入，不回显）把它写到 `~/.pi-env`，权限 600。做镜像前删除这个文件。
* 启动：以 `ecs-user` 身份在要工作的主机上执行 `pi-start`，或直接 `cd /opt/freesbc/test/perf/hosts/agents/<role> && pi`
  （等价于 `cd /opt/freesbc/test/perf/hosts/agents/<role> && pi --provider deepseek --model deepseek-flash`）。
  pi 会从 `~/.pi/agent`、当前目录及其父目录读取 `AGENTS.md`/`CLAUDE.md`，所以该主机的 `agents/<role>/AGENTS.md` 和仓库的 `CLAUDE.md` 都会被加载。
  一次性调用：`pi -p --provider deepseek --model deepseek-flash "<prompt>"`；`pi --list-models deepseek` 列出已知模型。
* 没有权限确认：pi 没有权限系统，它的 bash 工具以启动用户的权限运行，而 `ecs-user` 有免密 sudo。AGENTS.md 里的规则（不泄露密钥、只改列出的文件、
  不在 `provision.sh` 之外改 sysctl/防火墙、只 ssh 到计划里的主机、检查失败就停下并写证据）是**指令而不是强制**。真正的限制是安全组、一次性实例，
  以及 `gh` 只被允许在 A 上发 issue #109 的评论（见 AGENTS.md）。
* 分工：**loadgen** 的 agent 是驱动者：跑 `run.sh`、`daily-report.sh`，并通过 ssh 到 B 和 C。**sbc** 与 **switch** 的 agent 可选：
  在各自主机上负责 provision、服务启停和日志/指标查看。三者都把带时间戳的日志写到 `/opt/freesbc/results/<role>/notes.md`，并从 `/opt/freesbc/results/progress.md` 继续。
  地址一律读 `plan.env`，不要硬编码。
* 典型提示词（在 loadgen 上）：“读 progress.md，从第一个不是 done 的步骤继续。” / “跑 R13，汇报汇总里的关键行。” / “R15 失败了：收集证据，先不要重试。”

## 附录：主机没有公网 IP 时的出网

只在某台主机（以下称 C，即没有公网 IP 的那台）出不了网时才用。apt 走阿里云内网镜像（`mirrors.cloud.aliyuncs.com`），本来就不需要出网；
需要出网的只有 SIPp 源码包（github）、FreeSWITCH 镜像（Docker Hub）、Node/npm 与 pi（api.deepseek.com）。**先于 provision C（R05）完成**；按顺序试，一个通了就停。

已知事实（2026-10-17，旧的 C 实例）：把 C 的默认路由指向 A、A 做 MASQUERADE，**在这个 VPC 里不通**——A 的 NAT 计数器为 0，
VPC 路由器不会把下一跳是同子网另一台 ECS 的包转给它。所以方案 1 大概率不通，保留只是因为它自动回滚、试一次很便宜。

**方案 0（最低限度，不需要出网）**：不给 C 任何出网，R05 按文档从笔记本拷两个文件过去（SIPp 源码包、FreeSWITCH 镜像 tar），pi 不装在该主机上。
apt 走内网镜像，provision 其余部分都能做。需要 pi 在 C 上时再用下面的方案。（此时 R05 的两个文件都要准备。）

**方案 1：OS 路由经 A 做 NAT**（`provision.sh egress-gw` / `egress-client`）。已知在这个环境里很可能不通（见上面的已知事实），但流程是自动回滚的，值得一试：

```sh
ssh ecs-A 'sudo /opt/freesbc/test/perf/hosts/provision.sh egress-gw'
ssh ecs-C 'sudo /opt/freesbc/test/perf/hosts/provision.sh egress-client'
```

`egress-gw` 在 A 上开 `ip_forward`、对来自 `C_IP` 且去往子网之外的流量做 MASQUERADE（接口取 A 默认路由所在的网卡，不写死）、
FORWARD 只放行 `C_IP`（其余转发全丢），用 systemd oneshot `perf-egress.service` 持久化。
`egress-client` 在 C 上加 `default via A_IP metric 50`，当场 curl 测试，**不通就自己删掉路由并退出 1**（不会留下半坏状态）；通了才写 netplan 持久化。
子网的直连路由和 100.100.x 的元数据/DNS 路由始终不动，所以到 C 的 ssh 不受影响。

完成检查（从 C 上测）：

```sh
ssh ecs-C "curl -sS -m 8 -o /dev/null -w '%{http_code}\n' https://mirrors.aliyun.com; curl -sS -m 8 -o /dev/null -w '%{http_code}\n' https://api.deepseek.com; tracepath -n -m 3 223.5.5.5"
ssh ecs-A 'sudo iptables -t nat -L POSTROUTING -v -n | grep <C_IP>'     # 包计数器在增长
```

两个 curl 返回 200/301/401（不是 `000`），NAT 计数器大于 0，就是通了。**不通时撤销**（`egress-client` 已自动回滚路由；A 上的规则要手动撤）：

```sh
ssh ecs-C 'sudo /opt/freesbc/test/perf/hosts/provision.sh egress-client undo'
ssh ecs-A 'sudo /opt/freesbc/test/perf/hosts/provision.sh egress-gw undo'
ssh ecs-C 'ip -4 route show default'    # 应只有 DHCP 给的那一条 via 172.30.111.253 dev eth0 ... metric 100
```

**方案 a：VPC 路由表加一条 0.0.0.0/0 → 下一跳实例 A**（控制台操作，脚本不做）。VPC 路由器按目的 IP 转发，必须在这里指定下一跳：

1. 专有网络控制台 → 路由表 → 找到 vSwitch `172.30.96.0/20` 绑定的路由表（vSwitch 详情里有）。
2. “自定义路由” → 添加路由条目：目标网段 `0.0.0.0/0`，下一跳类型“ECS 实例”，选 A。
3. **副作用**：该路由对整个 vSwitch 生效（A、B、C）。A、B 有公网 IP，阿里云通常优先用自己的公网 IP 出网，但**必须马上验证**：
   从 A 和 B 各跑 `curl -sS -m 8 -o /dev/null -w '%{http_code}\n' https://mirrors.aliyun.com`，应仍是 301；A 上 `egress-gw` 的 MASQUERADE 只对 `C_IP` 生效，不会碰 A 自己的流量。
   如果 A 或 B 出网变坏，立刻删掉这条路由。
4. A 需要关闭 ECS 的“源/目的检查”（若控制台提供该选项），并运行方案 1 的 `egress-gw`；C 不需要改路由（默认路由本来指向网关 172.30.111.253，路由表把它转给 A）：
   `ssh ecs-C 'sudo /opt/freesbc/test/perf/hosts/provision.sh egress-client undo'` 先确保 C 没有残留的自定义默认路由。

完成检查同方案 1。

**方案 b：A 上的 HTTP(S) 代理**（`provision.sh proxy-gw` / `proxy-client`，即使方案 a 以后能用也先备好）：

```sh
ssh ecs-A 'sudo /opt/freesbc/test/perf/hosts/provision.sh proxy-gw'       # tinyproxy，监听 A_IP:3128，只允许 C_IP
ssh ecs-C 'sudo /opt/freesbc/test/perf/hosts/provision.sh proxy-client'
```

前提：A 的安全组放行 tcp 3128 来自 `C_IP`（上表）。`proxy-client` 配置 C 上的 apt（`/etc/apt/apt.conf.d/95perf-proxy`，内网镜像直连）、
Docker daemon（systemd drop-in）、`/etc/environment`（curl/git/go 的 `http(s)_proxy`，以及 pi 用的 `HTTPS_PROXY` 和 `NODE_USE_ENV_PROXY=1`）、npm（`/etc/npmrc`）、git（`/etc/gitconfig`），
并当场用代理 curl 三个地址、用 Node 访问 api.deepseek.com。

完成检查：`proxy-client` 的输出里 `via proxy: https://api.deepseek.com -> 401`；
`ssh ecs-C "curl -sS -m 8 -x http://<A_IP>:3128 -o /dev/null -w '%{http_code}\n' https://golang.google.cn"` 返回 200。
pi 经代理是否可用：看 `node (pi) via proxy` 那行，`401` 表示 Node 遵守了 `NODE_USE_ENV_PROXY`；`ERR …` 表示这个 Node 版本不遵守，
pi 在 C 上就用不了（要么给 C 上方案 a，要么不在 C 上跑 pi，由 A 的 agent 代为操作），**这一点未验证**。
撤销：`proxy-client undo`、`proxy-gw undo`。注意代理只解决 C 的出网；Docker Hub 对 A 也不通，所以 FreeSWITCH 镜像仍需 R05 的 tar 或镜像加速器。
