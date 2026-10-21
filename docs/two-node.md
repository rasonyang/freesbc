# Two FreeSBC nodes

FreeSBC targets small deployments, so high availability stays simple: two independent FreeSBC nodes in front of the same switch, and nothing shared between them. If a node is lost (a crash, or a drained restart), the calls in progress on it can drop, but the next call goes through the other node.

FreeSBC does nothing special for this. The two nodes never talk to each other. Everything that makes the next call take the other node is configuration on the carriers, the switch and the clients, described below. This follows the [scope rule](edge.md#scope-rule): failover between SBCs is decided by the party that dials them.

The concrete configuration is in [`examples/switch/freeswitch/`](../examples/switch/freeswitch/README.md) and [`examples/switch/asterisk/`](../examples/switch/asterisk/README.md) (section "Two FreeSBC nodes" in each README). Both run two nodes in Docker, and `test/run.sh` in each checks the failover. This guide says, for each switch behaviour it relies on, whether those tests exercise it. Anything marked "not exercised" is expected from the documentation or the code, not observed.

```text
      Carriers                 Clients (UDP, TCP, TLS, WSS)
         |   \                  /   |
         |    \                /    |
   public.ip A  public.ip B        (a client uses one node at a time)
         FreeSBC A     FreeSBC B
   private.ip A  private.ip B
            \           /
             \         /
              the switch
```

Test setup: node A has `public.ip` 203.0.113.7 and `private.ip` 10.77.0.2; node B has 203.0.113.8 and 10.77.0.3. The switch is 10.77.0.10.

## FreeSBC nodes

- **Own addresses.** Each node has its own `public.ip` and `private.ip`. The two nodes can share one config file with the addresses supplied through `${VAR}` ([`docs/config.md`](config.md)). `${VAR}` is expanded in string values, which includes `public.ip` and `private.ip`. The tests do this:

  ```yaml
  public: {ip: "${PUBLIC_IP}"}
  private: {ip: "${PRIVATE_IP}"}
  ```

  Start node A with `PUBLIC_IP=203.0.113.7 PRIVATE_IP=10.77.0.2`, node B with `203.0.113.8` and `10.77.0.3`. With systemd, put the two lines in `/etc/freesbc/freesbc.env` on each host (see [the environment file](install.md#environment-file)). `freesbc check` does not read that file; export the variables first.
- **Same `edge.switch` and `edge.carriers` on both nodes.** The pool hash (`edge.switch` with more than one entry, [`docs/edge.md`](edge.md#multiple-switches-edgeswitch)) picks the switch node from the order and content of the list, and a carrier is matched by the exact `host[:port]` in the switch's Request-URI. If the two nodes differ, the same user or the same carrier call takes a different path depending on the node. `edge.switch_carrier_port` and the `shield` limits should also match, so that either node can take over.
- **TLS certificate.** The top-level `tls` identity must cover the names clients use for both nodes: either one certificate with both names (or a wildcard) in its SANs, or one certificate per node if each node has its own name. A renewed certificate is only served after a restart (see "Rolling restart").
- **Size each node for the whole load.** `shield.max_sessions` and the `rtp` range are per node. After a failure the survivor carries every call, so give each node `rtp` and `shield.max_sessions` for the full load, not half of it. Calls already in progress stay on the node that holds them; only new calls move.
- **No active/standby with a floating IP.** This is not supported. `Run` fails unless `public.bind` and `private.ip` are both assigned to a local interface when it starts (`checkLocalAddr`, `internal/edge/edge.go:551-560`, called from `Run` at `internal/edge/edge.go:565-570`). A standby node that only receives the address after a failover would not have started. Run both nodes all the time, each with its own addresses.
- **Admin.** Each node has its own admin listener, metrics and drain state. Scrape and drain each node separately. Drain state is runtime only and is not shared.

## Carriers

The carrier must be able to reach the switch through either node. FreeSBC cannot do this for it.

**IP-authenticated trunks.** Allowlist both `public.ip` at the carrier. Give the carrier both SBC addresses (several destinations, or an SRV record) and have it fail over to the next address on `503` and on timeout. A draining node answers a new carrier call with `503` and `Retry-After: 30`, so a carrier that follows `503` moves on at once. The carrier side was only modelled in the tests: a simulator that tries the second SBC address on `503` or after a 3 s timeout. A real carrier's failover behaviour is not exercised.

**Registered trunks.** The switch registers an account with the carrier through a node. The carrier then sends calls to the registered Contact, and that Contact names that node: `sip:<user>@<public.ip>:<port>;fsbc=<token>`. Registering the same account through both nodes gives the carrier two Contacts (the same `fsbc=` token, since the token is derived from the switch node and the original Contact, and a different host). Many carriers keep one Contact per account, or pick one by their own rule, so the result is not predictable. Use one of these:

- **One carrier account per node** (recommended, and what both examples do). The FreeSWITCH example has `acct-a` through node A and `acct-a2` through node B; the Asterisk example has `acct` and `acct-b`. Each account has one Contact, on its node. The carrier is told to try both accounts. Tested with the carrier simulators only; the same account through both nodes was not exercised.
- **A short registration interval**, with one account. After a node is lost, the carrier's Contact for it goes stale until the account re-registers through the other node. Pick the interval accordingly.

The window in both cases is up to one registration interval after the node is lost: calls the carrier sends to the stale Contact fail until the registration is refreshed or expires (the carrier's own failover rules apply). The binding on a FreeSBC node lives for the granted expiry (`docs/edge.md`, "Carrier path"); the token is deterministic, so a restarted node accepts the same Contact again, but its binding table starts empty until the switch re-registers.

## Switch

The switch is the only place that knows both nodes.

### ACL and identify

List both `private.ip` where the switch decides who may use the carrier port.

- FreeSWITCH: `autoload_configs/acl.conf.xml`, list `freesbc_carrier`. A node missing from it gets `403` on every carrier call it delivers.
- Asterisk: `permit=` for each node in `acl.conf` (and the `identify` blocks, which name the carrier, not the node, so they do not change).

Exercised: both examples run both nodes through that ACL.

### Outbound carrier calls

Have one gateway (FreeSWITCH) or endpoint (Asterisk) per FreeSBC node, with `outbound-proxy` (and, in FreeSWITCH, `register-proxy`) at that node's `private.ip:5060`. Then try the nodes one after the other.

**FreeSWITCH.** A `bridge` string with one leg per carrier and node, and `continue_on_fail=true`:

```xml
<action application="set" data="continue_on_fail=true"/>
<action application="bridge" data="sofia/gateway/carrier-a-n1/${destination_number}|sofia/gateway/carrier-a-n2/${destination_number}"/>
```

The real strings are in `dialplan/default/00_freesbc_outbound.xml`. Tested on FreeSWITCH 1.10.12:

- **`503` (draining node): exercised.** The leg through A gets `503`, the bridge moves to the leg through B, and the carrier sees the call from node B's address.
- **Timeout (stopped node): exercised.** If the gateway is not yet marked DOWN, the INVITE to the dead node gets no answer and the bridge moves on after about 32 s (sofia's INVITE timeout, `RECOVERY_ON_TIMER_EXPIRE`). `leg_timeout` and `originate_timeout` are not needed and their variants are not exercised.
- **Gateway ping, OPTIONS `503` from a draining node: exercised.** The gateway goes DOWN on the first `503` (registered: `FAIL_WAIT`/`DOWN`; unregistered: `NOREG`/`DOWN (ping)`), and a DOWN gateway is skipped at once (`GATEWAY_DOWN`). After `DELETE /api/drain` the next ping brings it back UP, and REGED for a registered gateway, within about 40 s, with no action on the switch. Registrations keep refreshing through the draining node.
- **Set `register-proxy` on every gateway, with `ping` (15 s in the examples).** The ping goes to `register-proxy`, never to `outbound-proxy`. A gateway with `register=false` and no `register-proxy` pings the carrier directly, around FreeSBC, gets `408`, and stays DOWN for good. This was observed.
- **Gateway ping, dead node: exercised.** The ping times out (`408`, sofia's 32 s) and the gateway was DOWN 32-47 s after the stop with `ping=15`. Until then a bridge leg to the dead node costs about 32 s before it moves on.
- **Gateway ping answered `404` by a carrier: not exercised.**

**Asterisk.** Separate endpoints per node (`carrier-a` and `carrier-a-b`), and a `[via-nodes]` subroutine that runs `Dial` on node A's endpoint and then on node B's when `DIALSTATUS` is `CHANUNAVAIL` or `CONGESTION`. It does not move on for `NOANSWER` or `BUSY`, which are answers from the far end. Tested on Asterisk 22.10.1:

- **`503` (draining node): exercised.** `Dial` ends at once with `DIALSTATUS=CONGESTION`, `HANGUPCAUSE=34`, and the dialplan tries the next node's endpoint.
- **Qualify with OPTIONS `503` (draining node): exercised.** Asterisk counts any answer as reachable, so the contact stays `Avail`. Qualify does not detect a drain. The INVITE `503` handles it, as above.
- **Dead node, not yet qualified: exercised.** `Dial` ends with `CHANUNAVAIL`, `HANGUPCAUSE=18`, after about 33 s (the pjsip INVITE timer, not the `Dial` timeout), then tries node B.
- **Dead node, qualified: exercised.** With `qualify_frequency=30` and `qualify_timeout=3` (as shipped) the contact turns `Unavail` once a qualify times out, and `Dial` skips it at once (`CHANUNAVAIL`, cause 3).

### Agents

The switch reaches an agent through the Contact stored at registration, which names the node the agent registered through (`fsbc=` token and host). Calls to the agent go through that node with no per-node setting.

- **Agent on a draining node: exercised in both.** The agent still receives calls from the switch and can call out, because drain only refuses new carrier calls.
- **One Contact per AoR.** Prefer one Contact per user. If the agent re-registers through the other node, the new Contact replaces the old one, so the switch does not keep trying a node that is gone.
  - FreeSWITCH: `multiple-registrations=false` on the `internal` profile. Exercised: a REGISTER through B replaced the Contact registered through A, and moving back replaced it again. The behaviour without the parameter was not exercised.
  - Asterisk: `max_contacts=1` and `remove_existing=yes` on the client aor. Exercised: registering through B replaced the stale Contact, leaving one.
- **Stale Contact.** After a FreeSBC restart the binding table is empty, so a stored Contact carries an `fsbc=` token FreeSBC no longer knows, and FreeSBC answers `404`. The row stays until the client registers again.
  - FreeSWITCH: an INVITE to the user fails in 3-4 s with `UNALLOCATED_NUMBER` and the switch does not try anywhere else. Exercised.
  - Asterisk: `Dial` ends `CHANUNAVAIL` in 0-1 s. Qualify on a client does not clean it up: the contact stays `Avail` on `404`. Exercised with qualify on one test user. The shipped client aor keeps `qualify_frequency=0`; client qualify in general is not exercised.
  - A stale Contact to a node that is dead (not restarted): the INVITE times out after about 32 s on FreeSWITCH. Exercised. For Asterisk, the same 32 s applies as above for a carrier endpoint; the client case is not separately exercised.
- **Do not enable `all-reg-options-ping` with `unregister-on-options-fail` on FreeSWITCH.** In the test, after a `404` the switch expired the user (by user, not by contact) within about 45 s, even after the phone had re-registered through B, which broke a working agent.

### Media timeout

A call that was on a lost node has no media and no BYE, because FreeSBC's own watchdog (5 minutes) is gone with the node. Configure the switch so that it tears the channel down.

- FreeSWITCH: `rtp-timeout-sec` (60 on both profiles in the example). Exercised: a call that lost its node was hung up with `MEDIA_TIMEOUT` 60 s after the stop. The profile default of 300 would have held it five minutes.
- Asterisk: `rtp_timeout` (30 shipped; the test used 10). Exercised with a node killed (`docker kill`): the channels were torn down "for lack of audio RTP activity", and not while media flowed. A graceful stop of FreeSBC sends BYEs. The shipped 30 and `rtp_timeout_hold` for held calls were not exercised.

Keep the value above the longest silence a far end can send.

## Clients

A client registers through one node at a time. The switch holds its Contact on that node.

- **WebRTC, TCP and TLS clients.** Configure both nodes in the client: two WSS or TLS servers, or one DNS name with both addresses. When the node is lost, the connection closes, and the client reconnects (to the other address) and registers again. The new REGISTER replaces the old Contact if the switch keeps one Contact per AoR. Failover was modelled in the tests by a second registration through B, not by a real client reconnecting.
- **UDP phones.** A phone has no connection to lose, so it cannot know the node is gone until it registers again. Until then calls to it fail (stale Contact, above). Use a short registration interval and state the window to users: up to one registration interval after the node is lost. FreeSBC returns the interval from the switch's `200 OK`; set `expires` there.

## Rolling restart

Use this for an upgrade, a config change that is restart-only (everything except `shield.*`), or a renewed TLS certificate.

1. Make sure node B is up and healthy (`GET /api/health` on B).
2. `POST /api/drain` on A. New carrier calls move to B (`503` to the carrier and to the switch's gateway; FreeSWITCH also takes the gateway DOWN through its ping). Agents attached to A keep taking and placing calls, and registrations keep refreshing.
3. Poll `GET /api/drain` on A until `active_calls` is 0, or give up after a timeout of your choice. `active_calls` is also in `GET /api/status` and the metric is `freesbc_active_calls`; `freesbc_edge_draining` is 1 while draining.
4. Restart A. It starts not draining. Its clients reconnect and register again; the switch's stale Contacts on A fail until they do (see "Agents").
5. Wait until A is back (health ok; on FreeSWITCH the next ping brings the gateways UP, about 40 s; on Asterisk the next INVITE to A succeeds). Repeat from step 2 for B.

```sh
A=http://127.0.0.1:8080; O='Origin: http://127.0.0.1:8080'
curl -su admin:PASSWORD -X POST -H "$O" $A/api/drain
until [ "$(curl -su admin:PASSWORD $A/api/drain | jq .active_calls)" = 0 ]; do sleep 5; done
systemctl restart freesbc
```

Add a deadline to the loop if a stuck call must not block the restart. Details of drain: [`docs/edge.md`](edge.md#admission-and-abuse-controls).

## Known limits

- Calls in progress on a lost node are dropped. The switch ends them by the media timeout above, the far end by its own.
- Registered trunks and UDP phones have a window of up to one registration interval after a node is lost.
- Nothing is shared between the nodes: not registrations, bans, drain state or the config. A source banned on A is not banned on B, and each node needs the same config edits.
- A stale Contact stays on the switch until the client registers again (FreeSWITCH and Asterisk both). Neither switch's qualify or OPTIONS ping removes it, and on FreeSWITCH the registration OPTIONS ping is unsafe (see "Agents").
- No floating IP or active/standby.
- Not exercised: the same carrier account registered through both nodes, a real carrier or client doing the failover, TCP, TLS or WS carriers and clients, a switch pool behind the nodes, and switch versions other than FreeSWITCH 1.10.12 and Asterisk 22.10.1. The tests model carrier failover with simulators that try the second SBC address on `503` or after 3 s.
