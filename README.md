# Engagement Scope Gate

Check a proposed target inventory against a time-bounded rules-of-engagement record before handing it to assessment tooling. Deny rules override allow rules. Unlisted hosts, services, and protocols are rejected.

## Run

Python 3.12+, standard library only:

```sh
python scope_gate.py policy.example.json targets.example.json --at 2026-10-20T00:00:00Z
python -m unittest discover -v
```

The example deliberately contains denied targets and exits 1. Without `--at`, evaluation uses the current UTC time. Historical evaluation is for replay; a caller must not use an arbitrary past timestamp to authorize current activity.

## Policy semantics

- `valid_from` is inclusive and `valid_until` exclusive; both require timezones.
- `allow` and `deny` accept IP addresses, strict CIDRs, exact hostnames, and `*.domain` suffixes.
- A wildcard matches subdomains at any depth, excluding the apex. `*.example.test` cannot match `example.test.attacker.test`.
- Names are lowercased, converted to IDNA, and stripped of a final DNS dot.
- Services are explicit protocol/port pairs. TCP 443 does not authorize UDP 443.
- Each decision includes the engagement ID and a machine-readable reason.

Copy the example policy and replace its approval metadata with a real written authorization. JSON approval fields are records, not cryptographic proof of approval. Store the reviewed policy and evaluation output with engagement records.

## Trust boundary

This is an offline decision component. It does not enforce network egress, resolve DNS, prevent DNS rebinding, inspect URLs, or launch scans. A hostname authorization does not authorize its resolved IP automatically. Integrations must separately validate and pin every destination IP at connection time, validate redirect destinations, enforce the current approval window, and fail closed if this process exits nonzero. Keep direct scanner access restricted if this gate is part of a required control.

## Integration

Input targets are a JSON array of `{ "host": "192.0.2.5", "protocol": "tcp", "port": 443 }`. Malformed policies or target inventories exit 2. Never treat missing output as approval.
