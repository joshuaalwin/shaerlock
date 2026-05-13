# Ground truth: planted defects in `flawed-forward.txt`

Indices below are 1-based positions within the FORWARD chain (only `-A FORWARD` lines counted).

| FORWARD idx | Rule | Status |
|-------------|------|--------|
| 1 | `-m state --state ESTABLISHED,RELATED -j ACCEPT` | clean (stateful -- skipped from pairwise analysis) |
| 2 | `-i eth0 -o eth1 -s 192.168.1.0/24 -d 10.0.0.0/8 -p tcp --dport 443 -j ACCEPT` | clean |
| 3 | `-i eth0 -o eth1 -s 192.168.1.0/24 -d 10.0.0.0/8 -p tcp --dport 443 -j DROP` | **SHADOWING** (vs idx 2 -- identical match set, action differs) |
| 4 | `-i eth0 -o eth1 -s 192.168.1.0/24 -d 10.0.0.0/8 -p tcp --dport 80 -j ACCEPT` | clean |
| 5 | `-i eth0 -o eth1 -s 192.168.0.0/16 -d 10.0.0.0/8 -p tcp --dport 80 -j DROP` | **GENERALIZATION** (vs idx 4 -- idx-4 match is strict subset of idx-5 match, action differs) |
| 6 | `-i eth0 -o eth1 -p tcp --dport 8000:9000 -j ACCEPT` | clean |
| 7 | `-i eth0 -o eth1 -p tcp --dport 8500:9500 -j DROP` | **CORRELATION** (vs idx 6 -- overlap on ports 8500-9000, neither subset, action differs) |
| 8 | `-i eth0 -o eth1 -s 172.16.0.0/12 -d 10.0.0.0/8 -p udp --dport 53 -j ACCEPT` | clean |
| 9 | `-i eth0 -o eth1 -s 172.16.0.0/12 -d 10.0.0.0/8 -p udp --dport 53 -j ACCEPT` | **REDUNDANCY** (vs idx 8 -- identical match, same action) |

## Expected analyzer output (recall target = 4/4)

1. `SHADOWING` involving rule 3 (shadowed by rule 2)
2. `GENERALIZATION` of rule 4 by rule 5
3. `CORRELATION` between rules 6 and 7
4. `REDUNDANCY` involving rule 9 (subsumed by rule 8)
