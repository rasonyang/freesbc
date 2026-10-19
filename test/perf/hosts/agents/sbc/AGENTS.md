# AGENTS.md: sbc host (B), FreeSBC

You run on the FreeSBC host (B: `B_PUB_IP` public side, `B_PRIV_IP` private side; admin `127.0.0.1:8081`, user `admin`, password `perf`, throwaway). B is the system under test of the formal run: 4 vCPU / 8 GiB (Intel Xeon 6982P-C; fewer but much faster cores than the competitor's 6C/12T X5670; `GOMEMLIMIT` = `B_GOMEMLIMIT`, no MemoryMax), Ubuntu 24.04. eth0 (`B_PUB_IP`) is in the public vSwitch, eth1 (`B_PRIV_IP`, no default route) in the private one. Goal for today: have this host provisioned (`provision.sh sbc`, R04), record `lscpu`, memory and kernel in notes.md, and FreeSBC running the config the loadgen agent asks for (`freesbc-use sipp|fs|ast|stop`), healthy during runs, with metrics/profiles available (`curl -u admin:perf localhost:8081/metrics`, pprof to `/opt/freesbc/results/<date>/pprof/` when asked). Start with `ssh loadgen cat /opt/freesbc/results/progress.md`.

Read `/opt/freesbc/test/perf/hosts/STEPS.md` and `provision.sh` as references, not mandatory scripts: if something fails, diagnose it, fix it and retry; deviate when needed and log it.
ssh aliases `loadgen`, `sbc`, `switch` work from every host once `provision.sh` has run there (user `ecs-user`, key `~/.ssh/aicc-dev-ecs.pem`, passwordless sudo). Before that, use `ssh -i ~/.ssh/aicc-dev-ecs.pem ecs-user@<IP from plan.env>`. If `~/.ssh/aicc-dev-ecs.pem.pub` does not match the pem, OpenSSH offers the wrong key: rename the .pub.

## Addresses

Take every address from `/opt/freesbc/test/perf/hosts/plan.env` (`. plan.env`); never hard-code one. Two vSwitches: A and B's eth0 are in the public one, B's eth1 (`B_PRIV_IP`) and C in the private one; the VPC routes between them (A to C works; A to `B_PRIV_IP` does not and nothing needs it: B answers by eth0, where A's subnet is on-link, and the VPC drops a reply whose source is not that ENI's address). One security group.

## Guardrails

- Kit under `/opt/freesbc/test/perf/` (hosts kit, harness scripts, configs) may be edited to make things work. Before the first edit of a file: `cp file file.orig-$(date +%F)` (once). Log every change (what, why) under a `## changes` heading in `/opt/freesbc/results/sbc/notes.md`.
- Do not modify FreeSBC Go source (`/opt/freesbc/internal`, `/opt/freesbc/cmd`). A suspected FreeSBC bug: record `PROBLEM <step>: <one line> (evidence: <path>)` in notes.md with the commands and output, then work around it or move on.
- Never print or write secrets, tokens, ssh keys, `.pi-env`, password hashes, or public IPs (notes, results, comments).
- Do not change sshd configuration or authorized_keys mechanisms (no AuthorizedKeysCommand, no extra keys). If ssh between hosts fails, report it to the operator and wait.
- Do not touch cloud resources or security groups, or reboot/shut down anything. Do not delete results. No system changes beyond what this role needs.
- You own this host. The CPU limit for FreeSBC (`sbc-cores 1|2|all`, M03) is set by the loadgen agent over ssh, not by you. Do not restart FreeSBC or change its limits during a run you did not start. No `gh` on this host.
- Do not read `/etc/freesbc/key.pem`. After editing a FreeSBC config run `freesbc check -c <file>`.

## Logging

- Append timestamped lines (`date -Is`, step, what, result) to `/opt/freesbc/results/sbc/notes.md`.
- Shared state is `/opt/freesbc/results/progress.md` on loadgen: update it over ssh: `ssh loadgen /opt/freesbc/test/perf/hosts/progress.sh set R<nn> done|failed "note"`.
