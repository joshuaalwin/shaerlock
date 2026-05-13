# shaerlock -- Presentation Narration

Target: 10 minutes across 11 slides.
Timing markers are cumulative. `[PAUSE]` = 2-second breath. `[BEAT]` = 1-second beat.

---

## Slide 1 -- Title (~0:00 - 0:30)

> Hi everyone, I'm Joshua. My project is AI-Driven Firewall Rule Analysis and Evasion Detection. The tool is called shaerlock -- an iptables policy auditor I built for this course.

[PAUSE]

> The whole project comes down to one design choice: keep detection deterministic, and only let the LLM explain what the algorithm already found.

[BEAT]

> I'll walk through the architecture, the anomaly taxonomy, how the LLM is constrained, and the evaluation results. Eleven slides, ten minutes.

**[advance slide]**

---

## Slide 2 -- Problem (~0:30 - 1:40)

> So here's the problem.

[BEAT]

> Most AI security tools today put detection and explanation in the same model call. **[gesture to left card, "Conflated"]** The LLM finds the bug and describes the bug. Sounds reasonable, but it means hallucinations look exactly like findings. If the model invents a rule that doesn't exist, you have no way to tell from the output alone.

[PAUSE]

> Reproducibility is also gone. Run the same ruleset twice, you might get different findings depending on model temperature, context window, whatever.

[PAUSE]

> **[gesture to right card, "Separated"]** shaerlock refuses that design. A pairwise algorithm from Al-Shaer and Hamed, 2004, handles all the detection. The LLM only gets to narrate findings the algorithm already surfaced. And the eval harness counts every time the LLM references a rule index that doesn't exist in the input. We call those hallucinated rule indices, and we track them as a metric.

**[advance slide]**

---

## Slide 3 -- Course Angle (~1:40 - 2:30)

> This slide frames the project for ENPM693 specifically.

[BEAT]

> **[point to the quote block]** "The LLM does not find bugs. A deterministic algorithm does. The LLM only explains them, and the eval harness counts when it lies." That one sentence is the thesis.

[PAUSE]

> Three things carry the rest of the talk. **[point to each pillar as you name it]**

> First: defensive. The LLM is measured, not trusted. Second: reproducible. Same fixture, identical findings, every time. Third: cited. Every anomaly class maps back to a published paper. No invented references.

**[advance slide]**

---

## Slide 4 -- Architecture (~2:30 - 3:50)

> Here's the pipeline. Five stages, left to right.

[BEAT]

> **[point to Parser box]** Stage one: the parser. It takes raw iptables-save text and turns it into structured rule objects using regex and shlex. Nothing fancy.

> **[point to Analyzer box]** Stage two: the analyzer. This is where all the detection happens. It runs pairwise comparison across every rule pair in a chain -- O(n-squared) -- checking seven match dimensions: protocol, source CIDR, destination CIDR, source port, destination port, input interface, output interface. For each pair, it classifies the relationship into one of four anomaly classes. I'll show those on the next slide.

[PAUSE]

> **[point to Enricher box, outlined in red]** Stage three: the enricher. This is the only place the LLM lives. It takes each finding the analyzer already produced and asks the LLM to add severity, a plain-English explanation, and a suggested fix. The LLM operates under a strict JSON contract. It cannot reclassify, it cannot invent new findings.

> **[point to dashed line going down to the pluggable backend]** Two backends: Ollama for offline work, Anthropic for better narration quality. Same API contract for both.

> **[point to Evasion and CLI boxes]** Stages four and five: the evasion mapper links each anomaly class to a MITRE ATT&CK technique, and the CLI renders it all with Typer and Rich.

> **[point to bottom note]** The key constraint: the discovery path never touches the LLM. The LLM never sees a rule index it didn't receive from the analyzer.

**[advance slide]**

---

## Slide 5 -- Anomaly Taxonomy (~3:50 - 5:20)

> The taxonomy is from Al-Shaer and Hamed, IEEE INFOCOM 2004. It's a two-by-two grid over two predicates: the relationship between match sets, and whether the actions agree.

[PAUSE]

> **[point to SHADOWING, top-left]** SHADOWING. Rule j's match set is a subset of rule i's, but they have different actions. Rule j never fires. This is the dangerous one -- a security boundary vanishes silently. If you wrote a DROP rule and an earlier ACCEPT rule catches everything it would have caught, your DROP is dead code.

[BEAT]

> **[point to GENERALIZATION, top-right]** GENERALIZATION. Rule i is a strict subset of rule j, different actions. A broader rule later in the chain contradicts a tighter earlier one. Policy intent is unclear.

[BEAT]

> **[point to CORRELATION, bottom-left]** CORRELATION. The match sets overlap but neither is a subset of the other, and the actions differ. This is the subtle one. The outcome depends entirely on rule ordering, and that creates a rewrite-attack surface.

[BEAT]

> **[point to REDUNDANCY, bottom-right]** REDUNDANCY. Subset relationship, same action. Not a security bug, but it inflates the ruleset and makes auditing harder. Cleanup target.

[PAUSE]

> **[point to citation at bottom]** All four classes, same paper. This is settled taxonomy, not something I invented.

**[advance slide]**

---

## Slide 6 -- Evasion Linkage (~5:20 - 6:10)

> Each anomaly class maps to a concrete evasion technique, a MITRE ATT&CK ID, and the paper that describes it.

[BEAT]

> **[read down the table]** SHADOWING maps to IP fragmentation evasion, T1599, Ptacek and Newsham. GENERALIZATION maps to match-set widening, also T1599, Al-Shaer and Hamed. CORRELATION maps to order-dependent rule rewrite, T1599 again. REDUNDANCY maps to audit-gap abuse and tunneling, T1562.004, Wool 2004.

[PAUSE]

> Three of the four share the same ATT&CK ID -- T1599, Network Boundary Bridging. That's not an accident. Fragmentation, widening, and rule rewrite all exploit the gap between what the filter inspects and what the packet actually does on the wire.

> **[point to bottom note]** This table is hardcoded. The LLM is never asked to generate MITRE IDs. That keeps citation fidelity deterministic.

**[advance slide]**

---

## Slide 7 -- LLM Design (~6:10 - 7:15)

> **[point to left panel, the dark code block]** This is an excerpt of the system prompt the LLM receives. The key constraints: output must be valid JSON only. The anomaly classification is already fixed before the model sees the finding -- it cannot reclassify. And it can only reference rule indices that appear in the input. Anything else is forbidden.

[PAUSE]

> **[point to right panel, the big zero]** Across thirteen enrichments on the flawed ruleset using Anthropic, the hallucinated rule index count was zero. That means every time the LLM referenced a rule number, that rule actually existed in the input.

[BEAT]

> Zero isn't guaranteed. A different model, a different temperature, a longer ruleset might produce hallucinations. That's exactly why we measure it per-run instead of claiming it can't happen.

**[advance slide]**

---

## Slide 8 -- Evaluation (~7:15 - 8:10)

> Three numbers that summarize the evaluation.

[BEAT]

> **[point to first card]** 100% recall. Five planted defects in the flawed fixture, five detected. The deterministic analyzer missed nothing.

> **[point to second card]** Zero hallucinated rule indices out of thirteen LLM enrichments. Already covered on the last slide, but it earns its own card because it's the metric that separates this project from "just asking ChatGPT."

> **[point to third card]** Zero false positives on the clean control ruleset. A separate fixture with no planted defects produced zero findings. The analyzer doesn't cry wolf.

[PAUSE]

> **[point to severity bar at bottom]** The severity distribution across the thirteen enrichments: four HIGH, eight MEDIUM, one LOW. Quick sanity check -- a shadowed security boundary scores HIGH, a redundant rule scores LOW. That tracks with intuition.

**[advance slide]**

---

## Slide 9 -- Demo (~8:10 - 9:20)

> Two pieces of evidence on this slide.

[BEAT]

> **[point to left terminal panel]** On the left, the actual output of shaerlock audit running against the flawed fixture with no LLM. Thirteen findings across all four anomaly classes. All findings show the INPUT chain because the flawed fixture only has INPUT rules. Zero false negatives against the ground truth.

[PAUSE]

> **[point to right panel, the packet diagram]** On the right, the fragmentation demo. shaerlock includes a scapy-based demo that reproduces the Ptacek-Newsham fragmentation pattern on loopback.

> **[point to first two packet boxes]** Two fragments with IP ID 0xBEEF. Fragment one carries the UDP header plus the first eight bytes of payload. Fragment two carries the rest. Together they reassemble into one normal UDP datagram.

> **[point to the red-highlighted third box]** The third fragment has a different IP ID, 0xBEF0, and it overlaps with the first fragment's offset. On a network stack that prefers later-arriving fragments, this overlap rewrites the transport header after the firewall has already allowed the original packet through. That's the SHADOWING evasion reproduced in code. The pcap is captured on loopback and viewable in Wireshark.

[BEAT]

> **[point to citation]** Ptacek and Newsham, 1998. Same paper from the evasion table.

**[advance slide]**

---

## Slide 10 -- Conclusions (~9:20 - 9:50)

> Three contributions.

> **[point to contribution 1]** Detection and explanation are separated. The algorithm discovers; the LLM narrates under a JSON contract.

> **[point to contribution 2]** Hallucination is a measurable metric. The eval harness counts invented rule indices per run.

> **[point to contribution 3]** Evasion linkage is citation-bound. Hardcoded MITRE ATT&CK IDs and academic papers, not LLM-generated.

[PAUSE]

> **[point to bottom bar]** Code and reproduction instructions are on GitHub. Questions welcome.

**[advance slide]**

---

## Slide 11 -- References (~9:50 - 10:00)

> These are the six papers the project builds on, from Ptacek-Newsham 1998 through Lin et al. 2024. I'll leave this up for anyone who wants to note them down.

[PAUSE]

> Thank you.

---

## Timing summary

| Slide | Topic             | Start | End   | Duration |
|-------|-------------------|-------|-------|----------|
| 1     | Title             | 0:00  | 0:30  | 0:30     |
| 2     | Problem           | 0:30  | 1:40  | 1:10     |
| 3     | Course angle      | 1:40  | 2:30  | 0:50     |
| 4     | Architecture      | 2:30  | 3:50  | 1:20     |
| 5     | Taxonomy          | 3:50  | 5:20  | 1:30     |
| 6     | Evasion linkage   | 5:20  | 6:10  | 0:50     |
| 7     | LLM design        | 6:10  | 7:15  | 1:05     |
| 8     | Evaluation        | 7:15  | 8:10  | 0:55     |
| 9     | Demo              | 8:10  | 9:20  | 1:10     |
| 10    | Conclusions       | 9:20  | 9:50  | 0:30     |
| 11    | References        | 9:50  | 10:00 | 0:10     |

## Recording tips

- Practice the taxonomy slide (slide 5) a couple times. It's the densest slide and the one most likely to run long.
- The architecture slide (slide 4) is the second-longest. If you need to cut time, trim the per-box walkthrough and focus on the separation boundary between Analyzer and Enricher.
- On the demo slide (slide 9), if you're doing a live terminal demo instead of narrating the static slide, add 30-60 seconds for running the command and scrolling through output. Cut that time from slides 4 and 5.
- Speak slower than you think you need to. Recorded audio compresses pauses and makes fast speech unintelligible.
- The `[PAUSE]` markers are where you should take a breath and let the audience process. Do not skip them when recording.
