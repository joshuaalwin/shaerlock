# Fragmentation evasion demo

This demo is the offensive counterpart to a `SHADOWING` finding produced by
`shaerlock audit`. It emits overlapping IPv4 fragments to the loopback
interface and captures them with `tcpdump`, producing a `.pcap` file that
opens cleanly in Wireshark for the writeup.

The demo is **localhost-only** by construction: source and destination are
both `127.0.0.1`, and the payload is a synthetic `'A'*8 + 'B'*56` byte
string. There is no real exfiltration, no remote target, and no shellcode,
the artifact is the fragmentation pattern itself.

## What the demo shows

1. Three packets on `lo`, all UDP destined for `127.0.0.1:<port>`.
2. Two fragments share an IP `id` (`0xBEEF`), so Wireshark groups them as one
   reassembled datagram. The first carries the UDP header and the leading 8
   payload bytes (`MF=1, frag=0`); the second carries the rest (`MF=0,
   frag=1`).
3. A third fragment with a different `id` (`0xBEF0`) and `MF=1, frag=0`
   represents the late-arriving overlap whose role in the original Ptacek-
   Newsham mechanism is to overwrite the transport header on a downstream
   stack that prefers later fragments during reassembly.

## Why this maps to the SHADOWING anomaly class

A shadowed `DROP/REJECT` rule never fires, so its semantic intent disappears
from the active policy. A stateless filter upstream then judges incoming
flows on header values that an attacker can place in the *first* fragment.
A second fragment, arriving later with overlapping offsets, can change what
the receiving host actually sees, but the filter has already let the flow
through. The SHADOWING finding from `shaerlock` flags that the operator
*thought* the deny rule was in effect; in reality, the filter is only
inspecting the first fragment.

Reference: T. H. Ptacek and T. N. Newsham, "Insertion, Evasion, and Denial
of Service: Eluding Network Intrusion Detection," Secure Networks Inc.,
1998.

MITRE ATT&CK: `T1599 Network Boundary Bridging`.

## Reproducing the demo (≤ 60 s)

From the project root, with the venv built (`python -m venv .venv && pip
install -e '.[dev]'`):

```bash
sudo ./demo/capture.sh
# or, equivalently:
sudo .venv/bin/python -m ai_fw_audit.cli demo
```

This writes `demo/frag.pcap`. Open it in Wireshark:

```bash
wireshark demo/frag.pcap
```

In Wireshark you should see:

* Two `IPv4 Fragment` rows with the same `Identification: 0xBEEF` and a
  reassembled UDP packet whose data is `AAAAAAAA` followed by 56 `B` bytes.
* One additional `IPv4 Fragment` with `Identification: 0xBEF0` carrying
  `XXXXXXXX`, the would-be overlap.

## Caveats and ethical scope

* Linux's loopback path does not implement the same insertion/evasion
  ambiguity as a real-world stack-plus-NIC combination, so this demo is a
  *visualization* of the fragment-overlap pattern, not a claim that an
  attacker's payload bypassed a real defense in this run. Demonstrating an
  end-to-end bypass would require a router-with-stateless-filter topology
  in a VM lab, which is explicitly out of scope (see `docs/ARCHITECTURE.md`).
* No remote hosts are contacted. No real protocols are tunneled. The
  payload is a printable byte string with no executable semantics.
* Root is required for raw sockets and `tcpdump`; the demo refuses to run
  otherwise rather than silently degrading.
