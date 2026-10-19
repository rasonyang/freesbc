# AGENTS.md: switch host (C), FreeSWITCH and Asterisk

You run on the switch host (C: `C_IP`): SIPp UAS `:5060` (started by run.sh), Asterisk pjsip `:5080`, FreeSWITCH profile `perf` `:5090` (container `freeswitch-perf`, image `FS_IMAGE`, default `safarov/freeswitch:latest`, pulled through the registry mirror `DOCKER_REGISTRY_MIRROR` from plan.env; sessions-per-second and max-sessions raised for 1000+ CPS and thousands of sessions, RTP 20000-59999). Record the FreeSWITCH version in notes.md. C is in the private vSwitch (8 vCPU / 16 GiB; it keeps a public IP for ssh and downloads only). Goal for today: have this host provisioned (`provision.sh switch`, R05) and both switches ready and healthy for the runs (`fs_cli`, `asterisk -rx`, logs on request), accepting traffic only from `B_PRIV_IP`. Start with `ssh loadgen cat /opt/freesbc/results/progress.md`.

Read `/opt/freesbc/test/perf/hosts/STEPS.md` and `provision.sh` as references, not mandatory scripts: if something fails, diagnose it, fix it and retry; deviate when needed and log it.
ssh aliases `loadgen`, `sbc`, `switch` work from every host once `provision.sh` has run there (user `ecs-user`, key `~/.ssh/aicc-dev-ecs.pem`, passwordless sudo). Before that, use `ssh -i ~/.ssh/aicc-dev-ecs.pem ecs-user@<IP from plan.env>`. If `~/.ssh/aicc-dev-ecs.pem.pub` does not match the pem, OpenSSH offers the wrong key: rename the .pub.

## Addresses

Take every address from `/opt/freesbc/test/perf/hosts/plan.env` (`. plan.env`); never hard-code one. Two vSwitches: A and B's eth0 are in the public one, B's eth1 (`B_PRIV_IP`) and C in the private one; the VPC routes between them (A to C works; A to `B_PRIV_IP` does not and nothing needs it: B answers by eth0, where A's subnet is on-link, and the VPC drops a reply whose source is not that ENI's address). One security group.

## Guardrails

- Kit under `/opt/freesbc/test/perf/` (hosts kit, harness scripts, configs) may be edited to make things work. Before the first edit of a file: `cp file file.orig-$(date +%F)` (once). Log every change (what, why) under a `## changes` heading in `/opt/freesbc/results/switch/notes.md`.
- Do not modify FreeSBC Go source (`/opt/freesbc/internal`, `/opt/freesbc/cmd`). A suspected FreeSBC bug: record `PROBLEM <step>: <one line> (evidence: <path>)` in notes.md with the commands and output, then work around it or move on.
- Never print or write secrets, tokens, ssh keys, `.pi-env`, password hashes, or public IPs (notes, results, comments).
- Do not change sshd configuration or authorized_keys mechanisms (no AuthorizedKeysCommand, no extra keys). If ssh between hosts fails, report it to the operator and wait.
- Do not touch cloud resources or security groups, or reboot/shut down anything. Do not delete results. No system changes beyond what this role needs.
- You own this host. These switches accept REGISTER and calls without digest by design and only from `B_PRIV_IP`: never open them to another address, add a gateway/bridge/Dial to anything else, or widen the security-group assumptions.
- github.com is reachable from here (SIPp source is downloaded directly; the loadgen host's `provision.sh fetch-sipp` plus `scp` to `/var/tmp/` is the fallback). Docker Hub is not: use the registry mirror from plan.env (or `FS_IMAGE_TAR`). Do not restart a switch during a run you did not start. No `gh` on this host.

## Logging

- Append timestamped lines (`date -Is`, step, what, result) to `/opt/freesbc/results/switch/notes.md`.
- Shared state is `/opt/freesbc/results/progress.md` on loadgen: update it over ssh: `ssh loadgen /opt/freesbc/test/perf/hosts/progress.sh set R<nn> done|failed "note"`.
