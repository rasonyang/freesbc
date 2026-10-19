# Progress

One line per step: `ID | status | date | note`. R-steps are in STEPS.md (setup, smoke, end of
day), M-steps in MEASURE.md (the measurements of the formal run, issue #109). Status is todo,
done or failed. Edit with `test/perf/hosts/progress.sh set ID status "note"`, never by hand-
reformatting. The first step that is not `done` is where the next session continues. Lives on
the loadgen host in /opt/freesbc/results/progress.md and is pulled to the laptop with the other
results.

R00 | todo | - | environment check on all three hosts, plan.env filled in
R01 | todo | - | console: two vSwitches, B's second ENI, security group
R02 | todo | - | ssh as ecs-user, repo rsynced to /opt/freesbc on all three hosts
R03 | todo | - | provision.sh loadgen, self-check PASS
R04 | todo | - | provision.sh sbc, self-check PASS
R05 | todo | - | provision.sh switch, self-check PASS
R06 | todo | - | ecs-user ssh keys distributed, all self-checks PASS, ssh aliases work
R07 | done | - | pi agent already installed on all three hosts (nothing to do)
R08 | todo | - | smoke SWITCH=sipp: call, 5 users
R09 | todo | - | smoke FreeSWITCH: call, 5 users
M03 | todo | - | competitor scenario (50 CPS to 1000 concurrent, 600 s): all cores, 4, 2; SIPp, then FreeSWITCH
M01 | todo | - | CPS steps without media: call, carrier-in, carrier-out
M02 | todo | - | concurrent G.711 calls up to 80% CPU / loss limit
M04 | todo | - | registrations held, REGISTER/s at refresh
M05 | todo | - | WebRTC handshakes/s and concurrent SRTP calls
M06 | todo | - | FreeSWITCH as the switch: CPS steps and concurrency
M07 | todo | - | pprof CPU, goroutine, heap at the peak of M01 and M02; #170 RSS per CPS
M08 | todo | - | 8 h soak at 70% of the M02 maximum
R18 | todo | - | end of day: report posted, tarball rebuilt, pulled
