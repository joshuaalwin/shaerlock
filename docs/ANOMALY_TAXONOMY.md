# Anomaly taxonomy

Formalized after Al-Shaer & Hamed [1, 2] for the four anomaly classes
implemented in `shaerlock`. The fifth class in the original taxonomy,
*irrelevance*, requires network topology context and is explicitly out of
scope for this project.

## Notation

For each rule `R = (proto, src, dst, sport, dport, in_iface, out_iface,
action)`, the *match set* `M(R)` is the set of all packets whose header
fields satisfy every component of `R`. A wildcard component (`None`) is
the universe of values for that component. Element-wise:

* `proto`: `M_proto(R)` = `{R.proto}` if specified, else `{tcp, udp,
  icmp, …}` (all).
* `src`, `dst`: `M_addr(R)` = the IP block specified by the CIDR, else
  `0.0.0.0/0`.
* `sport`, `dport`: `M_port(R)` = the inclusive interval `[low, high]`,
  else `[0, 65535]`.
* `in_iface`, `out_iface`: `M_iface(R)` = `{R.iface}` if specified, else
  any interface.

`M(R) = M_proto × M_src × M_dst × M_sport × M_dport × M_in × M_out`.

For two rules in the same chain, `R_i` (earlier, smaller index) and
`R_j` (later, larger index), with actions `A_i, A_j`:

## Definitions

### REDUNDANCY (case 1: subsuming duplicate)

```
M_j ⊆ M_i  ∧  A_i = A_j   →   REDUNDANCY
```

Every packet that matches `R_j` also matches `R_i`, and they take the
same action. `R_j` is therefore unreachable and contributes no semantics
to the policy.

### REDUNDANCY (case 2: foldable special case)

```
M_i ⊊ M_j  ∧  A_i = A_j   →   REDUNDANCY
```

`R_i` is a strictly narrower restatement of `R_j` with the same action.
The policy could fold `R_i` into `R_j` without changing meaning.

### SHADOWING

```
M_j ⊆ M_i  ∧  A_i ≠ A_j   →   SHADOWING
```

`R_j` is unreachable: every packet that would match it has already been
disposed of by `R_i` with the opposite action. The operator's intent
encoded in `R_j` is silently absent from the active policy. This is the
class linked to fragmentation evasion in the `evasion.py` table because
the *intended* deny disappears, leaving only the broader allow.

### GENERALIZATION

```
M_i ⊊ M_j  ∧  A_i ≠ A_j   →   GENERALIZATION
```

`R_i` is a strict special-case carve-out before a broader rule with the
opposite action. This is the legitimate way to express "deny X, allow
everything else": `R_i` is the carve-out and `R_j` is the catch-all.
But it is also a frequent source of bugs when the operator believes
they have written a deny boundary that, in fact, only fires for the
narrow case.

### CORRELATION

```
M_i ∩ M_j ≠ ∅  ∧  ¬(M_j ⊆ M_i)  ∧  ¬(M_i ⊆ M_j)  ∧  A_i ≠ A_j
                                       →   CORRELATION
```

Two rules with overlapping but neither-subset match sets and different
actions. The packets in `M_i ∩ M_j` are disposed of by whichever rule
appears first; *reordering changes the policy meaning*. This is a
latent bypass: a future merge, refactor, or reorder can silently flip
the policy.

## Implementation notes

* `match_subset(a, b)` in `analyzer.py` is the conjunction of element-
  wise containment checks: protocol-supersedes, CIDR
  `subnet_of`, port-range `contains`, interface-supersedes (None is
  wildcard).
* `match_intersects(a, b)` is the conjunction of element-wise
  intersection checks: protocol-overlaps, CIDR `overlaps`, port-range
  `intersects`, interface-overlaps.
* The classification cascade in `_classify_pair` is exhaustive over the
  three primary cases (`j ⊆ i`, `i ⊊ j`, neither) and emits at most one
  finding per ordered pair.
* Rules with `-m state` / `-m conntrack`, negation, or unhandled match
  modules, and loopback-only rules (`-i lo` / `-o lo`), are excluded
  from pairwise comparison. The exclusion list is rendered as a
  separate panel by `cli.py` so the operator sees the scope honestly.

## References

[1] E. Al-Shaer and H. Hamed, "Discovery of Policy Anomalies in
Distributed Firewalls," *IEEE INFOCOM*, 2004.

[2] E. Al-Shaer, H. Hamed, R. Boutaba, and M. Hasan, "Conflict
Classification and Analysis of Distributed Firewall Policies," *IEEE
J. Sel. Areas Commun.*, vol. 23, no. 10, 2005.
