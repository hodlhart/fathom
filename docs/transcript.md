# A hunt, end to end — **STUB**

> **This transcript is from a STUB, not a live console.** It was produced by
> `scripts/transcript.py`, which starts `scripts/stub_console.py` and drives the
> real MCP server over stdio. The stub's payload shapes were transcribed from a
> running Weirvern console on 2026-11-23 and then rewritten onto RFC 5737
> documentation addresses and `example.com` names. No deployment's address,
> hostname or credential appears here.
>
> What it proves: each tool assembles a request, parses the console's shape, and
> returns text a model can read. What it does not prove: that your deployment
> answers the same way. That is `scripts/live_check.py`, against your console.
>
> Regenerate with:
>
> ```bash
> .venv/bin/python scripts/transcript.py > docs/transcript.md
> ```

**Question:** *Is anything on this segment beaconing? Start from the correlated
findings and show me the evidence, not just the score.*

**Answer, in one paragraph:** `192.0.2.10` is talking to `198.51.100.66:443` in
42 short flows, has a high detector score corroborated by two families, and
resolved `beacon.example.com` immediately before the window. The traffic volume is
small and the cadence is fixed. That is the beacon shape rather than the busy-host
shape. The hunt ends with a block proposal for an operator to decide, not a block.

## 1. Start from the correlation, not the alert list

The engine has already grouped evidence into ripples. Reading the group first avoids re-deriving it from individual decisions.

**Call** `list_ripples(hours=24, limit=5)`

**Answer**

```text
Ripples in the last 24h, newest first (1 found):

  192.0.2.10 at 2026-11-19T09:45:00 score 8.31 p=0.00042 severity medium [conn_volume, dns_entropy]
    2 independent families: conn, dns
    connection count rose to twelve times this host's baseline while DNS query entropy rose, in the same window
      - conn_volume, at 1h, above, p=0.003, 310.0 vs baseline 25.0
      - dns_entropy, at 1h, above, p=0.012, 3.9 vs baseline 2.1
```

## 2. Read the detector rows behind it

The ripple says conn and dns moved together. The anomaly rows name the score, the models that voted and the feature that moved.

**Call** `list_anomalies(hours=24, limit=5)`

**Answer**

```text
Anomalies in the last 24h, severity counts high 1, medium 1:
  2026-11-19T10:00:00  192.0.2.10  0.94  0.91  Isolation Forest,Adaptive Baseline
  2026-11-19T10:00:00  192.0.2.11  0.61  0.54  LOF
```

## 3. Describe the host

Before calling anything malicious, establish what is normal for this address: volume, peers, ports and the Zeek services it uses.

**Call** `get_host(addr='192.0.2.10')`

**Answer**

```text
Host 192.0.2.10:
totals:
  bytes: 5048
  packets: 37
  flows: 54
  unique_destinations: 2
  unique_ports: 2
  first_seen: 2026-11-19T09:45:00
  last_seen: 2026-11-19T10:00:00
top destinations:
  198.51.100.66  -  812  42  1
  192.0.2.53  -  140  9  1
top ports:
  443  6  812  42
  53  17  140  9
zeek services:
  ssl  42  812
  dns  9  140
```

## 4. Follow the conversation

The host's top destination is outside the documentation prefix. The flow table gives the port, byte count and flow count for that pair.

**Call** `hunt_flows(src='192.0.2.10', hours=24, limit=5)`

**Answer**

```text
Flows for src 192.0.2.10 in the last 24h (54 flows, 3 pairs):
  192.0.2.10  198.51.100.66  443  812  42
  192.0.2.10  192.0.2.53  53  140  9
  192.0.2.11  192.0.2.10  445  4096  3
```

## 5. Ask what it resolved

A fixed external address is weaker evidence than a name. DNS shows what the host looked up, which is the part that survives reassignment.

**Call** `dns_names(hours=24, limit=5)`

**Answer**

```text
Names resolved in the last 24h (2 total):
  2026-11-19T10:00:00  192.0.2.10  beacon.example.com  A  NOERROR
  2026-11-19T10:00:00  192.0.2.11  cdn.example.com  A  NOERROR
```

## 6. Read the protocol log

The DNS log aggregates by host and name, so the resolver conversation is visible without pulling every query.

**Call** `query_zeek(log='dns', hours=24, limit=5)`

**Answer**

```text
Zeek dns log, last 24h:
  192.0.2.10  42  beacon.example.com
  192.0.2.11  9  cdn.example.com
```

## 7. Assemble the evidence for the finding

The anomaly's window start turns a score into a bundle: the anomaly record, the flow summary, freshness per source, and the Zeek records behind it.

**Call** `get_finding_evidence(addr='192.0.2.10', start='2026-11-19T09:45:00')`

**Answer**

```text
Evidence for 192.0.2.10 from 2026-11-19T09:45:00:
  src_addr: 192.0.2.10
  window_start: 2026-11-19T09:45:00
  window_end: 2026-11-19T10:00:00
anomaly:
  anomaly_score: 0.94
  severity: high
  detected_by_models: Isolation Forest,Adaptive Baseline
  primary_deviation_feature: conn_volume
  severity_basis: two independent families
  review_state: open
flow_summary:
  bytes: 5048
  packets: 37
  flows: 54
  unique_destinations: 2
  unique_ports: 2
  first_seen: 2026-11-19T09:45:00
  last_seen: 2026-11-19T10:00:00
source_freshness:
  flows: {"state": "fresh", "age_s": 42.0}
  zeek_conn: {"state": "fresh", "age_s": 51.0}
  zeek_ssl: {"state": "fresh", "age_s": 51.0}
  zeek_dns: {"state": "fresh", "age_s": 44.0}
  zeek_notice: {"state": "fresh", "age_s": 61.0}
flows: 1 item(s)
  192.0.2.10  198.51.100.66  443  812  42
zeek_conn: 1 item(s)
  2026-11-19T10:00:00  198.51.100.66  443  tcp  ssl  SF
zeek_ssl: 1 item(s)
  2026-11-19T10:00:00  198.51.100.66  443  TLSv13  beacon.example.com  ok
zeek_dns: 1 item(s)
  2026-11-19T10:00:00  192.0.2.53  beacon.example.com  A  NOERROR
notice: 0 item(s)
  (nothing in this window)
```

## 8. Orient in the segment's traffic

Top talkers, protocol mix and destination spread separate a busy host from a host talking to one place on a fixed interval.

**Call** `top_talkers(hours=24, limit=5)`

**Answer**

```text
Traffic shape over the last 24h:
busiest talkers:
  192.0.2.10  -  5048  54  2
  192.0.2.11  -  4096  3  1
protocols:
  6  TCP  4908  45
  17  UDP  140  9
ports:
  443  6  812  42
  53  17  140  9
volume:
  2026-11-19T09:00:00  2000  22
  2026-11-19T10:00:00  3048  32
spread:
  192.0.2.10  2  54
  192.0.2.11  1  3
noise:
  flows: 0
  bytes: 0
```

## 9. Check the pipeline before trusting the silence

The self-audit answers a different question: are the sensors and rules healthy? A silent sensor can make a segment look quiet.

**Call** `alert_audit(hours=24, limit=5)`

**Answer**

```text
Pipeline audit for the last 24h, counts silent_sensor 1, expired_rules 1:
  warn  silent_sensor  sensor-a  silent for 2h (stale after 45s)
  info  expired_rules  sluice  1 blocking rule expired during the window
```

## 10. File the proposal, and stop there

The evidence points at one host. This records a proposal with the reasoning attached; nothing is blocked until an operator applies it in the console.

**Call** `propose_block(host='192.0.2.10', reason="steady beacon to 198.51.100.66:443, twelve times the host's baseline connection count with near-zero payload, corroborated by DNS entropy in the 09:45 window", evidence='ripple window 2026-11-19T09:45:00; anomaly score 0.94; beacon.example.com', ttl_minutes=60)`

**Answer**

```text
Proposed blocking 192.0.2.10 (id bp_00000000deadbeef). NOTHING IS BLOCKED YET: an operator must apply it in the console. Duration: 60 min.
```

## What the transcript does not show

- A real deployment's addresses, names or volumes. The stub carries one
  synthetic host so the thread is easy to follow.
- A successful token mint. The stub accepts any credential; the console's
  token card has a deployment prerequisite, described in the README.
- That the proposal was applied. It was not, and cannot be: only an
  operator can apply one, and the tool says so in its answer.
