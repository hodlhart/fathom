---
name: threat-hunt
description: Investigate a flagged host and decide what it means.
---

# Threat hunt

Turns a detector score into a conclusion that can survive being read by someone else. The
method is: find out what fired, identify the host, pivot on its actual traffic, compare it
against its own history and against the segment, then state what the evidence supports and
what it does not.

One rule governs the whole thing. A score is a model output, not a finding. The finding is
the traffic, so nothing is concluded until traffic has been read.

## When to use

- An alert needs triage, or someone asks "is this host compromised".
- A host is behaving strangely and the question is what it is talking to.
- You need evidence for a write-up, an escalation, or a proposed block.

Do not use it to answer "what is happening on the network" with no host or alert in mind.
That is `top_talkers` and a browse, not a hunt.

## Procedure

1. Establish what fired. Call `list_anomalies(hours=24)`.
   Done when you have the host, the score, and which models contributed to it.
2. Read what the alerting already decided. Call `alert_audit(hours=24)`.
   Done when you know whether this finding was reviewed and what the disposition was. A
   finding already adjudicated as benign is a different conversation from a new one.
3. Identify the host before trusting it as a victim. Call `get_host(addr)`.
   Done when you can say whether its volume is ordinary for that host, who it talks to, and
   which ports it serves. A scanner's source address is not a compromised host.
4. Pivot on the traffic, not the score. Call `hunt_flows(src=addr, hours=24)`, and re-run it
   with `port=` if one destination port dominates.
   Done when you can name the destinations, the byte and flow counts, and the shape: one peer
   and lots of bytes, many peers and few bytes, or steady low volume to one place.
5. Put names on the destinations. Call `dns_names(hours=24)` and, when a name appears,
   `query_zeek(log="dns", hours=24)`.
   Done when you can say whether the destination names are ordinary for this segment or are
   resolved by this host alone. A name only one host ever looks up is the finding.
6. Compare the host against the segment. Call `top_talkers(hours=24)`.
   Done when you know whether the host is an outlier or whether the whole segment is loud. An
   outlier is a finding. Everything being loud is a different, upstream problem.
7. Assemble the argument the console would make. Call `get_finding_evidence(addr, start)`.
   Done when you have the evidence block, so the write-up quotes the record instead of
   paraphrasing your impression of it.
8. Conclude in one of three states, and name which check produced it: CORROBORATED (traffic
   supports it), REFUTED (traffic explains it benignly), or INSUFFICIENT DATA (the reads did
   not answer the question). Done when the conclusion names the window, the host, and the
   traffic evidence.
9. Only when CORROBORATED and the destination is external, call
   `propose_block(host, reason, evidence, ttl_minutes)` with the reason and the evidence you
   actually used. Done when you have stated to the reader that this PROPOSES and does not
   block anything.

## Pitfalls

- `propose_block` blocks nothing. It records a proposal a person applies. Reporting a host as
  blocked after calling it is wrong, and it is the kind of wrong that gets acted on.
- An empty result is ambiguous. No rows can mean "nothing happened" or "the read failed", and
  those need opposite next steps. Read the tool's own message before deciding which.
- Do not hunt an address you have not identified. Step 3 exists because a scan source, a
  gateway and a victim all look the same in a score.
- Every statement is scoped to the window you asked for. "No traffic to that name" is only
  true of the hours you queried, so put the window in the conclusion.
- A single loud flow is not a pattern. Distinguish one large transfer from sustained contact,
  because the second is the one that indicates a channel.
- Do not stop at step 8 and call INSUFFICIENT DATA a result. Say which read would have
  answered the question, so the next person can run it.

## Verification

The conclusion is finished when it contains all four of these:

- the host and the time window, stated explicitly;
- at least one piece of traffic evidence (bytes, flow counts, peers, or names), not only a
  score;
- the three-way state, with the check that produced it;
- what was not checked, and what would settle it if the state is INSUFFICIENT DATA.

If a block was proposed, quote the reason and evidence strings you passed, so a reader can
check them against the ledger.
