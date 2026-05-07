# References

IEEE-numbered. Cited from `docs/ARCHITECTURE.md`,
`docs/ANOMALY_TAXONOMY.md`, `docs/EVALUATION.md`,
`ai_fw_audit/evasion.py`, and `demo/README.md`.

[1] E. Al-Shaer and H. Hamed, "Discovery of Policy Anomalies in
Distributed Firewalls," in *Proc. IEEE INFOCOM*, Hong Kong, 2004,
pp. 2605–2616.

[2] E. Al-Shaer, H. Hamed, R. Boutaba, and M. Hasan, "Conflict
Classification and Analysis of Distributed Firewall Policies," *IEEE
J. Sel. Areas Commun.*, vol. 23, no. 10, pp. 2069–2084, Oct. 2005.

[3] A. Wool, "A Quantitative Study of Firewall Configuration Errors,"
*IEEE Computer*, vol. 37, no. 6, pp. 62–67, Jun. 2004.

[4] T. H. Ptacek and T. N. Newsham, "Insertion, Evasion, and Denial of
Service: Eluding Network Intrusion Detection," Secure Networks, Inc.,
Tech. Rep., Jan. 1998.

[5] C. Diekmann, L. Hupel, J. Michaelis, M. Haslbeck, and G. Carle,
"Verified iptables Firewall Analysis and Verification," *J. Automated
Reasoning*, vol. 61, no. 1–4, pp. 191–242, Jun. 2018.

[6] L. Yuan, J. Mai, Z. Su, H. Chen, C.-N. Chuah, and P. Mohapatra,
"FIREMAN: A Toolkit for FIREwall Modeling and ANalysis," in *Proc. IEEE
Symp. Security and Privacy*, Berkeley, CA, May 2006, pp. 199–213.

[7] MITRE Corporation, "MITRE ATT&CK," 2024. [Online]. Available:
https://attack.mitre.org/. Specific techniques cited in
`ai_fw_audit/evasion.py`:

* `T1599`, *Network Boundary Bridging.*
* `T1562.004`, *Impair Defenses: Disable or Modify System Firewall.*
* `T1572`, *Protocol Tunneling* (referenced in the evasion-table
  notes for `REDUNDANCY` but not implemented as a demo).

[8] Netfilter Project, "iptables-save / iptables-restore, Linux
manual page," in *Linux man-pages*. [Online]. Available:
https://man7.org/linux/man-pages/man8/iptables-save.8.html

[9] Netgate, "pfSense Documentation, Scrub / Packet Normalization,"
2024. [Online]. Available:
https://docs.netgate.com/pfsense/en/latest/firewall/scrub.html

[10] Ollama, "Ollama, local LLM runtime," 2024. [Online]. Available:
https://ollama.com

[11] Anthropic, "Claude API, message format and structured outputs,"
2024. [Online]. Available:
https://docs.anthropic.com/en/api/messages

[12] T. Lin, J. Sun, J. Yang, et al., "From Code to Compromise:
Evaluating Large Language Models for Security Policy Audit and
Generation," *arXiv:2407.07930*, 2024.
