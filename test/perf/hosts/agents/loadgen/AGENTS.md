# AGENTS.md: loadgen host (A), the driver

You run on the load generator (A: `A_IP`, `A_CARRIERGEN_IP`, `A_CARRIER_UAS_IP`, optional `A_LOADGEN2_IP`) of the FORMAL run of FreeSBC's perf harness (issue #109). You drive the others. Goal for today: run `MEASURE.md` (M01 to M08) as far as it goes, in its order, judging every run with `runcheck.sh` and recording results in `results/<date>/measure-results.md` and `progress.sh`; start the 8 hour soak (`m08.sh`) in the background at the load you derive from M02; post the day report to #109 (`daily-report.sh`, scrubbed) and, when the soak has ended, a soak report. Start with `cat /opt/freesbc/results/progress.md` and `progress.sh next`.

Long jobs (`run.sh` ladders, `m03.sh`, the soak) run detached with nohup or tmux, write a log file and are polled; never block one tool call for more than a minute or two. You limit FreeSBC's cores yourself over ssh (`ssh sbc sudo sbc-cores N|all`), B's agent does not.
Do not tune FreeSBC or the harness to improve numbers; if you change a parameter to get a run through, put it in the report.

Read `/opt/freesbc/test/perf/hosts/STEPS.md` and `provision.sh` as references, not mandatory scripts: if something fails, diagnose it, fix it and retry; deviate when needed and log it.
ssh aliases `loadgen`, `sbc`, `switch` work from every host once `provision.sh` has run there (user `ecs-user`, key `~/.ssh/aicc-dev-ecs.pem`, passwordless sudo). Before that, use `ssh -i ~/.ssh/aicc-dev-ecs.pem ecs-user@<IP from plan.env>`. If `~/.ssh/aicc-dev-ecs.pem.pub` does not match the pem, OpenSSH offers the wrong key: rename the .pub.

## Addresses

Take every address from `/opt/freesbc/test/perf/hosts/plan.env` (`. plan.env`); never hard-code one. Two vSwitches: A and B's eth0 are in the public one, B's eth1 (`B_PRIV_IP`) and C in the private one; the VPC routes between them (A to C works; A to `B_PRIV_IP` does not and nothing needs it: B answers by eth0, where A's subnet is on-link, and the VPC drops a reply whose source is not that ENI's address). One security group.

## Guardrails

- Kit under `/opt/freesbc/test/perf/` (hosts kit, harness scripts, configs) may be edited to make things work. Before the first edit of a file: `cp file file.orig-$(date +%F)` (once). Log every change (what, why) under a `## changes` heading in `/opt/freesbc/results/loadgen/notes.md` and list them in the day's `summary.md` (daily-report.sh does it from the `*.orig-*` backups).
- Do not modify FreeSBC Go source (`/opt/freesbc/internal`, `/opt/freesbc/cmd`). A suspected FreeSBC bug: record `PROBLEM <step>: <one line> (evidence: <path>)` in notes.md with the commands and output, then work around it or move on.
- Never print or write secrets, tokens, ssh keys, `.pi-env`, password hashes, or public IPs (notes, results, comments).
- Do not change sshd configuration or authorized_keys mechanisms (no AuthorizedKeysCommand, no extra keys). If ssh between hosts fails, report it to the operator and wait.
- Do not touch cloud resources or security groups, or reboot/shut down anything. Do not delete results. No system changes beyond what this role needs.
- You may inspect `sbc` and `switch` and help their agents; say so in their `notes.md` (or yours) when you change anything there.
- `gh` is allowed for exactly one thing: `gh issue comment 109 --repo rasonyang/freesbc --body-file <scrubbed file>` (the day report from `daily-report.sh`, and the soak report when the soak has ended). Before posting, grep the file for public IPv4s, keys and passwords (`grep -nEi '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|password|secret|token|BEGIN'`; 172.30.* is fine); if anything matches, do not post, fix the file.
- Operator-only: plan.env edits after a recreate, image creation, releasing instances.

## Logging

- Append timestamped lines (`date -Is`, step, what, result) to `/opt/freesbc/results/loadgen/notes.md`.
- Shared state is `/opt/freesbc/results/progress.md` on loadgen: you own it; `progress.sh set R<nn> done|failed "note"` after each step.
