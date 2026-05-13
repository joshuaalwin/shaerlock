// shaerlock — ENPM693 Final Presentation
// Build with: node build.js
// Output: shaerlock.pptx

const PptxGenJS = require("pptxgenjs");

const NAVY = "1E2761";
const ICE = "CADCFC";
const WHITE = "FFFFFF";
const NEAR_BLACK = "0A0F2C";
const MUTED = "5A6378";
const ACCENT = "F96167";

const FONT_TITLE = "Georgia";
const FONT_BODY = "Calibri";
const FONT_MONO = "Courier New";

const W = 13.33;
const H = 7.5;

const pres = new PptxGenJS();
pres.layout = "LAYOUT_WIDE";
pres.title = "shaerlock — ENPM693 Final";
pres.author = "Joshua Alwin";
pres.company = "University of Maryland — ENPM693";

// ----- helpers -----
function darkBg(slide) {
  slide.background = { color: NAVY };
}

function lightBg(slide) {
  slide.background = { color: "F7F8FB" };
  // top accent bar
  slide.addShape("rect", { x: 0, y: 0, w: W, h: 0.18, fill: { color: NAVY } });
}

function pageNumber(slide, n, total, dark = false) {
  slide.addText(`${n} / ${total}`, {
    x: W - 1.0, y: H - 0.45, w: 0.8, h: 0.3,
    fontFace: FONT_BODY, fontSize: 10,
    color: dark ? ICE : MUTED, align: "right",
  });
}

function brandTag(slide, dark = false) {
  slide.addText("shaerlock · ENPM693", {
    x: 0.5, y: H - 0.45, w: 4, h: 0.3,
    fontFace: FONT_BODY, fontSize: 10,
    color: dark ? ICE : MUTED, italic: true,
  });
}

function sectionHeader(slide, label) {
  // colored circle + label
  slide.addShape("ellipse", {
    x: 0.5, y: 0.45, w: 0.35, h: 0.35,
    fill: { color: NAVY },
    line: { color: NAVY },
  });
  slide.addText("§", {
    x: 0.5, y: 0.45, w: 0.35, h: 0.35,
    fontFace: FONT_TITLE, fontSize: 18, bold: true,
    color: WHITE, align: "center", valign: "middle",
    margin: 0,
  });
  slide.addText(label, {
    x: 0.95, y: 0.42, w: 8, h: 0.4,
    fontFace: FONT_BODY, fontSize: 14,
    color: MUTED, bold: true, charSpacing: 2,
  });
}

function title(slide, text, opts = {}) {
  slide.addText(text, {
    x: 0.5, y: 0.85, w: W - 1.0, h: 1.05,
    fontFace: FONT_TITLE, fontSize: opts.size || 32, bold: true,
    color: opts.color || NAVY,
  });
}

const TOTAL = 11;

// ============================================================
// Slide 1 — Title (dark)
// ============================================================
{
  const s = pres.addSlide();
  darkBg(s);

  // Decorative monogram circle
  s.addShape("ellipse", {
    x: 1.0, y: 2.4, w: 1.6, h: 1.6,
    fill: { color: NAVY }, line: { color: ICE, width: 2 },
  });
  s.addText("🔍", {
    x: 1.0, y: 2.4, w: 1.6, h: 1.6,
    fontSize: 60, color: ICE, align: "center", valign: "middle",
    margin: 0,
  });

  s.addText("shaerlock", {
    x: 3.2, y: 2.55, w: 9, h: 1.2,
    fontFace: FONT_TITLE, fontSize: 64, bold: true,
    color: WHITE,
  });

  s.addText("Auditing iptables with separated detection and explanation.", {
    x: 3.2, y: 3.7, w: 9, h: 0.6,
    fontFace: FONT_BODY, fontSize: 20, italic: true,
    color: ICE,
  });

  // bottom band
  s.addShape("rect", {
    x: 0, y: H - 1.2, w: W, h: 1.2,
    fill: { color: NEAR_BLACK }, line: { color: NEAR_BLACK },
  });
  s.addText("ENPM693 — Network Security · Final Project", {
    x: 0.5, y: H - 1.05, w: 12, h: 0.4,
    fontFace: FONT_BODY, fontSize: 16, color: ICE, charSpacing: 1.5,
  });
  s.addText("Joshua Alwin · University of Maryland · 2026", {
    x: 0.5, y: H - 0.55, w: 12, h: 0.4,
    fontFace: FONT_BODY, fontSize: 16, color: ICE, bold: true,
  });

  s.addNotes(
    "Title slide. Hi everyone — I'm Joshua. This is shaerlock, " +
    "an iptables policy auditor I built for ENPM693. The whole project " +
    "is about a single idea: keep detection deterministic, and let the " +
    "LLM only explain. Ten minutes, eleven slides — let's go."
  );
}

// ============================================================
// Slide 2 — Problem & motivation
// ============================================================
{
  const s = pres.addSlide();
  lightBg(s);
  sectionHeader(s, "PROBLEM");
  title(s, "Conflating detection and explanation makes hallucinations undetectable.");

  const rowY = 2.2;
  const colW = 5.8;

  // Left card — the bad pattern
  s.addShape("roundRect", {
    x: 0.5, y: rowY, w: colW, h: 4.4,
    fill: { color: "FFFFFF" }, line: { color: "E2E5EE", width: 1 },
    rectRadius: 0.1,
  });
  s.addText("Conflated", {
    x: 0.8, y: rowY + 0.2, w: colW - 0.6, h: 0.5,
    fontFace: FONT_TITLE, fontSize: 22, bold: true, color: ACCENT,
  });
  s.addText([
    { text: "Detection ", options: { bold: true, color: NAVY } },
    { text: "and ", options: { color: MUTED } },
    { text: "explanation ", options: { bold: true, color: NAVY } },
    { text: "live in the same model call.", options: { color: MUTED } },
  ], {
    x: 0.8, y: rowY + 0.85, w: colW - 0.6, h: 0.7,
    fontFace: FONT_BODY, fontSize: 16,
  });
  s.addText([
    { text: "→ Hallucinations look like findings.", options: { breakLine: true } },
    { text: "→ Reproducibility is at the model's mercy.", options: { breakLine: true } },
    { text: "→ No metric separates discovery from prose.", options: {} },
  ], {
    x: 0.8, y: rowY + 1.55, w: colW - 0.6, h: 2.6,
    fontFace: FONT_BODY, fontSize: 16, color: NAVY, paraSpaceAfter: 14,
  });

  // Right card — what we did
  s.addShape("roundRect", {
    x: 7.0, y: rowY, w: colW, h: 4.4,
    fill: { color: NAVY }, line: { color: NAVY },
    rectRadius: 0.1,
  });
  s.addText("Separated", {
    x: 7.3, y: rowY + 0.2, w: colW - 0.6, h: 0.5,
    fontFace: FONT_TITLE, fontSize: 22, bold: true, color: ICE,
  });
  s.addText([
    { text: "Discovery ", options: { bold: true, color: WHITE } },
    { text: "is a deterministic algorithm. ", options: { color: ICE } },
    { text: "The LLM only narrates.", options: { bold: true, color: WHITE } },
  ], {
    x: 7.3, y: rowY + 0.85, w: colW - 0.6, h: 0.9,
    fontFace: FONT_BODY, fontSize: 16,
  });
  s.addText([
    { text: "→ Pairwise Al-Shaer & Hamed (2004).", options: { breakLine: true } },
    { text: "→ LLM constrained to JSON, indices fixed.", options: { breakLine: true } },
    { text: "→ Hallucinations are counted, not believed.", options: {} },
  ], {
    x: 7.3, y: rowY + 1.7, w: colW - 0.6, h: 2.6,
    fontFace: FONT_BODY, fontSize: 16, color: ICE, paraSpaceAfter: 14,
  });

  brandTag(s);
  pageNumber(s, 2, TOTAL);

  s.addNotes(
    "Most 'AI security' tools today let an LLM both find and explain " +
    "policy issues in the same call. That makes hallucinations indistinguishable " +
    "from findings. Our approach refuses that conflation: a pairwise algorithm " +
    "from Al-Shaer and Hamed 2004 finds the bugs; the LLM is only allowed to " +
    "narrate them under a strict JSON contract."
  );
}

// ============================================================
// Slide 3 — Course angle
// ============================================================
{
  const s = pres.addSlide();
  lightBg(s);
  sectionHeader(s, "COURSE ANGLE");
  title(s, "shaerlock uses AI as an auditor, not a detector.");

  // big quote-like callout
  s.addShape("roundRect", {
    x: 0.7, y: 2.2, w: 11.9, h: 2.8,
    fill: { color: ICE }, line: { color: NAVY, width: 0 },
    rectRadius: 0.15,
  });
  s.addText("“", {
    x: 0.6, y: 1.75, w: 1.2, h: 1.6,
    fontFace: FONT_TITLE, fontSize: 110, bold: true, color: NAVY,
  });
  s.addText(
    "The LLM does not find bugs. A deterministic algorithm does.\n" +
    "The LLM only explains them — and the eval harness counts when it lies.",
    {
      x: 1.7, y: 2.4, w: 10.5, h: 2.4,
      fontFace: FONT_TITLE, fontSize: 22, italic: true,
      color: NAVY, paraSpaceAfter: 8,
    }
  );

  // three pillars row
  const pY = 5.5;
  const items = [
    { icon: "1", h: "Defensive", b: "LLM measured, not trusted." },
    { icon: "2", h: "Reproducible", b: "Same fixture, identical findings." },
    { icon: "3", h: "Cited", b: "Each anomaly maps to a paper." },
  ];
  items.forEach((it, i) => {
    const x = 0.7 + i * 4.1;
    s.addShape("ellipse", {
      x, y: pY, w: 0.5, h: 0.5,
      fill: { color: NAVY }, line: { color: NAVY },
    });
    s.addText(it.icon, {
      x, y: pY, w: 0.5, h: 0.5, margin: 0,
      fontFace: FONT_TITLE, fontSize: 18, bold: true,
      color: WHITE, align: "center", valign: "middle",
    });
    s.addText(it.h, {
      x: x + 0.65, y: pY - 0.05, w: 3.4, h: 0.4,
      fontFace: FONT_BODY, fontSize: 18, bold: true, color: NAVY,
    });
    s.addText(it.b, {
      x: x + 0.65, y: pY + 0.35, w: 3.4, h: 0.5,
      fontFace: FONT_BODY, fontSize: 16, color: MUTED,
    });
  });

  brandTag(s);
  pageNumber(s, 3, TOTAL);

  s.addNotes(
    "ENPM693 framing. We're a defensive course, so the goal is to use AI " +
    "as an auditor — measurable, reproducible, citation-bound. Three pillars " +
    "carry the rest of the talk: defensive use, reproducibility, citation."
  );
}

// ============================================================
// Slide 4 — Architecture pipeline
// ============================================================
{
  const s = pres.addSlide();
  lightBg(s);
  sectionHeader(s, "ARCHITECTURE");
  title(s, "A five-stage pipeline keeps the LLM out of the detection path.");

  const stages = [
    { name: "Parser", sub: "regex / shlex", color: NAVY },
    { name: "Analyzer", sub: "Al-Shaer pairwise · O(n²)", color: NAVY },
    { name: "Enricher", sub: "constrained JSON", color: ACCENT },
    { name: "Evasion", sub: "MITRE ATT&CK map", color: NAVY },
    { name: "CLI", sub: "typer + rich", color: NAVY },
  ];

  const startX = 0.5, startY = 2.6, boxW = 2.35, boxH = 1.6, gap = 0.2;
  stages.forEach((st, i) => {
    const x = startX + i * (boxW + gap);
    s.addShape("roundRect", {
      x, y: startY, w: boxW, h: boxH,
      fill: { color: WHITE },
      line: { color: st.color, width: st.color === ACCENT ? 3 : 2 },
      rectRadius: 0.1,
    });
    s.addText(st.name, {
      x, y: startY + 0.15, w: boxW, h: 0.55,
      fontFace: FONT_TITLE, fontSize: 20, bold: true,
      color: st.color, align: "center",
    });
    s.addText(st.sub, {
      x: x + 0.1, y: startY + 0.75, w: boxW - 0.2, h: 0.7,
      fontFace: FONT_BODY, fontSize: 14, italic: true,
      color: MUTED, align: "center",
    });
    if (i < stages.length - 1) {
      const ax = x + boxW;
      s.addText("▶", {
        x: ax - 0.02, y: startY + boxH / 2 - 0.18, w: 0.25, h: 0.36,
        fontFace: FONT_BODY, fontSize: 18, bold: true,
        color: NAVY, align: "center", valign: "middle", margin: 0,
      });
    }
  });

  // Pluggable backend callout under Enricher
  const enricherX = startX + 2 * (boxW + gap);
  s.addShape("line", {
    x: enricherX + boxW / 2, y: startY + boxH,
    w: 0, h: 0.45, line: { color: ACCENT, width: 2, dashType: "dash" },
  });
  s.addShape("roundRect", {
    x: enricherX - 0.7, y: startY + boxH + 0.5, w: boxW + 1.4, h: 0.9,
    fill: { color: ICE }, line: { color: ACCENT, width: 1 }, rectRadius: 0.08,
  });
  s.addText("pluggable backend", {
    x: enricherX - 0.7, y: startY + boxH + 0.55, w: boxW + 1.4, h: 0.3,
    fontFace: FONT_BODY, fontSize: 14, italic: true, color: ACCENT, align: "center",
  });
  s.addText("Ollama (offline-first)   ⇄   Anthropic", {
    x: enricherX - 0.7, y: startY + boxH + 0.85, w: boxW + 1.4, h: 0.5,
    fontFace: FONT_BODY, fontSize: 16, bold: true, color: NAVY, align: "center",
  });

  // bottom note
  s.addText(
    "Discovery never sees the LLM. The LLM never sees a rule index it didn't already get.",
    {
      x: 0.5, y: 6.3, w: 12.3, h: 0.45,
      fontFace: FONT_BODY, fontSize: 16, italic: true,
      color: MUTED, align: "center",
    }
  );

  brandTag(s);
  pageNumber(s, 4, TOTAL);

  s.addNotes(
    "Five-stage pipeline. Parser → Analyzer is purely deterministic. " +
    "Enricher is the only stage where the LLM lives, with two pluggable " +
    "backends — Ollama for offline, Anthropic for the better narration. " +
    "Evasion mapper hardcodes the MITRE linkage to keep citations honest."
  );
}

// ============================================================
// Slide 5 — Anomaly taxonomy (2x2 grid)
// ============================================================
{
  const s = pres.addSlide();
  lightBg(s);
  sectionHeader(s, "TAXONOMY");
  title(s, "Four set-theoretic classes cover all pairwise rule conflicts.");

  const cards = [
    {
      name: "SHADOWING",
      pred: "M_j ⊆ M_i  ∧  A_i ≠ A_j",
      cons: "Rule j never fires; security boundary disappears silently.",
      color: ACCENT,
    },
    {
      name: "GENERALIZATION",
      pred: "M_i ⊂ M_j  ∧  A_i ≠ A_j",
      cons: "Wider rule contradicts a tighter earlier one.",
      color: NAVY,
    },
    {
      name: "CORRELATION",
      pred: "M_i ∩ M_j ≠ ∅  ∧  A_i ≠ A_j",
      cons: "Order-dependent ambiguity — rewrite-attack surface.",
      color: NAVY,
    },
    {
      name: "REDUNDANCY",
      pred: "M_j ⊆ M_i  ∧  A_i = A_j",
      cons: "Cosmetic, but it inflates audit gap and rule sprawl.",
      color: NAVY,
    },
  ];

  const gx = [0.5, 6.95];
  const gy = [2.0, 4.6];
  const cw = 5.85, ch = 2.3;

  cards.forEach((c, i) => {
    const x = gx[i % 2], y = gy[Math.floor(i / 2)];
    s.addShape("roundRect", {
      x, y, w: cw, h: ch,
      fill: { color: WHITE }, line: { color: "E2E5EE", width: 1 },
      rectRadius: 0.1,
    });
    s.addShape("rect", {
      x, y, w: 0.12, h: ch,
      fill: { color: c.color }, line: { color: c.color },
    });
    s.addText(c.name, {
      x: x + 0.3, y: y + 0.15, w: cw - 0.5, h: 0.5,
      fontFace: FONT_TITLE, fontSize: 22, bold: true, color: c.color,
      charSpacing: 1,
    });
    s.addText(c.pred, {
      x: x + 0.3, y: y + 0.7, w: cw - 0.5, h: 0.5,
      fontFace: FONT_MONO, fontSize: 16, color: NAVY, bold: true,
    });
    s.addText(c.cons, {
      x: x + 0.3, y: y + 1.3, w: cw - 0.5, h: 0.85,
      fontFace: FONT_BODY, fontSize: 16, color: MUTED, italic: true,
    });
  });

  // Citation
  s.addText("(Al-Shaer & Hamed, IEEE INFOCOM 2004)", {
    x: 0.5, y: H - 0.8, w: 12, h: 0.35,
    fontFace: FONT_BODY, fontSize: 14, color: MUTED, italic: true,
  });

  brandTag(s);
  pageNumber(s, 5, TOTAL);

  s.addNotes(
    "The taxonomy is Al-Shaer & Hamed 2004. Two predicates over match-sets " +
    "and actions cleanly separate four classes. SHADOWING is the dangerous " +
    "one — a security rule that never fires. CORRELATION is the subtle one — " +
    "order-dependent ambiguity that often hides a rewrite attack."
  );
}

// ============================================================
// Slide 6 — Evasion linkage table
// ============================================================
{
  const s = pres.addSlide();
  lightBg(s);
  sectionHeader(s, "EVASION LINKAGE");
  title(s, "Every anomaly class maps to a published technique and MITRE ATT&CK ID.");

  const headers = ["Anomaly", "Technique", "ATT&CK", "Citation"];
  const rows = [
    ["SHADOWING", "IP fragmentation evasion", "T1599", "Ptacek & Newsham 1998"],
    ["GENERALIZATION", "Match-set widening", "T1599", "Al-Shaer & Hamed 2004"],
    ["CORRELATION", "Order-dependent rule rewrite", "T1599", "Al-Shaer & Hamed 2004"],
    ["REDUNDANCY", "Audit-gap abuse / tunneling", "T1562.004", "Wool 2004"],
  ];

  const tbl = [
    headers.map((h) => ({
      text: h,
      options: {
        bold: true, color: WHITE, fill: { color: NAVY },
        fontFace: FONT_BODY, fontSize: 16, align: "left",
        valign: "middle",
      },
    })),
    ...rows.map((r, i) =>
      r.map((cell, j) => ({
        text: cell,
        options: {
          fontFace: j === 0 ? FONT_BODY : (j === 2 ? FONT_MONO : FONT_BODY),
          fontSize: 16,
          bold: j === 0 || j === 2,
          color: j === 0 ? NAVY : (j === 2 ? ACCENT : NEAR_BLACK),
          fill: { color: i % 2 === 0 ? WHITE : ICE },
          valign: "middle",
        },
      }))
    ),
  ];

  s.addTable(tbl, {
    x: 0.6, y: 2.2, w: 12.1,
    colW: [2.4, 4.5, 1.6, 3.6],
    rowH: 0.75,
    border: { type: "solid", pt: 1, color: "E2E5EE" },
  });

  s.addText(
    "Linkage is a hardcoded table — the LLM is not asked to invent " +
    "MITRE IDs. Reproducibility and citation fidelity over novelty.",
    {
      x: 0.6, y: 6.1, w: 12.1, h: 0.6,
      fontFace: FONT_BODY, fontSize: 16, italic: true, color: MUTED,
      align: "center",
    }
  );

  brandTag(s);
  pageNumber(s, 6, TOTAL);

  s.addNotes(
    "Each anomaly maps to a MITRE technique and a citation. Three of four " +
    "are T1599, Network Boundary Bridging — fragmentation, widening, and " +
    "rule rewrite all live there. REDUNDANCY is T1562.004, Impair Defenses. " +
    "Crucially, this table is hardcoded — the LLM is not allowed to invent it."
  );
}

// ============================================================
// Slide 7 — LLM design + hallucination metric
// ============================================================
{
  const s = pres.addSlide();
  lightBg(s);
  sectionHeader(s, "LLM DESIGN");
  title(s, "A strict JSON contract produced zero hallucinated rule indices.");

  // Left: constrained system prompt excerpt
  s.addShape("roundRect", {
    x: 0.5, y: 2.2, w: 7.6, h: 4.2,
    fill: { color: NEAR_BLACK }, line: { color: NEAR_BLACK },
    rectRadius: 0.1,
  });
  s.addText("system prompt (excerpt)", {
    x: 0.7, y: 2.3, w: 7.4, h: 0.35,
    fontFace: FONT_BODY, fontSize: 14, color: ICE, italic: true,
  });
  const promptLines =
    "{\n" +
    "  \"role\": \"firewall-policy auditor\",\n" +
    "  \"contract\": {\n" +
    "    \"output\":  \"valid JSON only\",\n" +
    "    \"class\":   \"FIXED — do not reclassify\",\n" +
    "    \"rules\":   \"reference ONLY indices in input\",\n" +
    "    \"forbidden\": [\"invent rules\",\n" +
    "                   \"prose outside JSON\"]\n" +
    "  },\n" +
    "  \"emit\": [\"severity\", \"explanation\",\n" +
    "           \"suggested_fix\"]\n" +
    "}";
  s.addText(promptLines, {
    x: 0.7, y: 2.7, w: 7.4, h: 3.6,
    fontFace: FONT_MONO, fontSize: 14, color: ICE,
  });

  // Right: stat callout 0/13
  s.addShape("roundRect", {
    x: 8.4, y: 2.2, w: 4.4, h: 4.2,
    fill: { color: NAVY }, line: { color: NAVY }, rectRadius: 0.1,
  });
  s.addText("hallucinated rule indices", {
    x: 8.4, y: 2.4, w: 4.4, h: 0.4,
    fontFace: FONT_BODY, fontSize: 16, color: ICE, align: "center", italic: true,
  });
  s.addText("0", {
    x: 8.4, y: 2.8, w: 4.4, h: 2.2,
    fontFace: FONT_TITLE, fontSize: 200, bold: true,
    color: WHITE, align: "center", valign: "middle",
  });
  s.addText("/ 13 enrichments", {
    x: 8.4, y: 5.0, w: 4.4, h: 0.5,
    fontFace: FONT_BODY, fontSize: 18, color: ICE, align: "center",
  });
  s.addText("Anthropic · flawed-ruleset.txt", {
    x: 8.4, y: 5.6, w: 4.4, h: 0.4,
    fontFace: FONT_BODY, fontSize: 14, color: ICE, align: "center", italic: true,
  });

  brandTag(s);
  pageNumber(s, 7, TOTAL);

  s.addNotes(
    "The LLM gets a strict JSON contract. Classification is fixed before the " +
    "model sees the finding. Rule indices are restricted to those already in " +
    "the input. The eval harness counts any index outside that set as a " +
    "hallucination. Across thirteen enrichments, the count was zero."
  );
}

// ============================================================
// Slide 8 — Evaluation results
// ============================================================
{
  const s = pres.addSlide();
  lightBg(s);
  sectionHeader(s, "EVALUATION");
  title(s, "100% recall on planted defects, zero hallucinations, zero false positives.");

  const stats = [
    { num: "100%", label: "Recall", sub: "5 of 5 planted defects" },
    { num: "0 / 13", label: "Hallucinations", sub: "no invented rule indices" },
    { num: "0", label: "False positives", sub: "on clean control ruleset" },
  ];

  const cardW = 3.9, cardH = 3.0, cardY = 2.2;
  stats.forEach((st, i) => {
    const x = 0.5 + i * (cardW + 0.25);
    s.addShape("roundRect", {
      x, y: cardY, w: cardW, h: cardH,
      fill: { color: WHITE }, line: { color: NAVY, width: 2 },
      rectRadius: 0.12,
    });
    // accent vertical stripe on the left (matches taxonomy slide motif)
    s.addShape("rect", {
      x, y: cardY + 0.15, w: 0.12, h: cardH - 0.3,
      fill: { color: i === 1 ? ACCENT : NAVY }, line: { color: i === 1 ? ACCENT : NAVY },
    });
    s.addText(st.num, {
      x, y: cardY + 0.4, w: cardW, h: 1.5,
      fontFace: FONT_TITLE, fontSize: 60, bold: true,
      color: NAVY, align: "center",
    });
    s.addText(st.label, {
      x, y: cardY + 1.95, w: cardW, h: 0.5,
      fontFace: FONT_BODY, fontSize: 18, bold: true,
      color: ACCENT, align: "center",
    });
    s.addText(st.sub, {
      x: x + 0.2, y: cardY + 2.45, w: cardW - 0.4, h: 0.5,
      fontFace: FONT_BODY, fontSize: 16, italic: true,
      color: MUTED, align: "center",
    });
  });

  // severity distribution mini-bar
  s.addText("Severity distribution (13 LLM enrichments)", {
    x: 0.5, y: 5.5, w: 12.3, h: 0.35,
    fontFace: FONT_BODY, fontSize: 14, italic: true, color: MUTED,
  });
  const sevs = [
    { k: "HIGH", v: 4, c: ACCENT },
    { k: "MEDIUM", v: 8, c: NAVY },
    { k: "LOW", v: 1, c: ICE },
  ];
  const total = 13;
  let bx = 0.5;
  const by = 5.9, bh = 0.5, bwTotal = 12.3;
  sevs.forEach((sv) => {
    const w = (sv.v / total) * bwTotal;
    s.addShape("rect", {
      x: bx, y: by, w, h: bh,
      fill: { color: sv.c }, line: { color: sv.c },
    });
    s.addText(`${sv.k} ${sv.v}`, {
      x: bx, y: by, w, h: bh,
      fontFace: FONT_BODY, fontSize: 14, bold: true,
      color: sv.c === ICE ? NAVY : WHITE,
      align: "center", valign: "middle",
    });
    bx += w;
  });

  brandTag(s);
  pageNumber(s, 8, TOTAL);

  s.addNotes(
    "Three results. Hundred percent recall against five planted defects. " +
    "Zero hallucinated rule indices across thirteen LLM enrichments. " +
    "Zero findings on the clean control ruleset. The severity bar shows " +
    "the LLM's distribution — and a quick spot-check shows it tracks " +
    "intuitive severity: a vanished security boundary scores HIGH, a " +
    "duplicate rule scores LOW."
  );
}

// ============================================================
// Slide 9 — Demo evidence
// ============================================================
{
  const s = pres.addSlide();
  lightBg(s);
  sectionHeader(s, "DEMO");
  title(s, "The fragmentation demo reproduces Ptacek-Newsham 1998 on loopback.");

  // Left: terminal-style "shaerlock audit" evidence
  s.addShape("roundRect", {
    x: 0.5, y: 2.2, w: 6.3, h: 4.4,
    fill: { color: NEAR_BLACK }, line: { color: NEAR_BLACK }, rectRadius: 0.1,
  });
  s.addText("$ shaerlock audit --no-llm flawed-ruleset.txt", {
    x: 0.7, y: 2.3, w: 6.0, h: 0.4,
    fontFace: FONT_MONO, fontSize: 14, color: ICE,
  });
  const auditExcerpt =
    "ruleset: tests/fixtures/flawed-ruleset.txt\n" +
    "chains : INPUT     rules: 12\n" +
    "\n" +
    " class            chain  i   j\n" +
    " ──────────────   ─────  ─  ──\n" +
    " REDUNDANCY       INPUT  3   4\n" +
    " SHADOWING        INPUT  5   6\n" +
    " CORRELATION      INPUT  7   8\n" +
    " GENERALIZATION   INPUT 10   9\n" +
    " SHADOWING        INPUT 11  12\n" +
    " …  13 findings  ·  0 false negatives";
  s.addText(auditExcerpt, {
    x: 0.7, y: 2.75, w: 6.0, h: 3.8,
    fontFace: FONT_MONO, fontSize: 14, color: ICE, valign: "top",
  });

  // Right: fragmentation demo card
  s.addShape("roundRect", {
    x: 7.0, y: 2.2, w: 5.8, h: 4.4,
    fill: { color: WHITE }, line: { color: "E2E5EE", width: 1 }, rectRadius: 0.1,
  });
  s.addText("$ sudo shaerlock demo → frag.pcap", {
    x: 7.2, y: 2.3, w: 5.4, h: 0.4,
    fontFace: FONT_MONO, fontSize: 14, color: NAVY,
  });

  // packet diagram
  const pY = 2.9;
  const packets = [
    { id: "id=0xBEEF  MF=1  off=0", payload: "UDP hdr + AAAAAAAA", color: NAVY },
    { id: "id=0xBEEF  MF=0  off=1", payload: "BBBB…BBBB (56 B)", color: NAVY },
    { id: "id=0xBEF0  MF=1  off=0", payload: "overlap fragment",   color: ACCENT },
  ];
  packets.forEach((p, i) => {
    const py = pY + i * 1.0;
    s.addShape("roundRect", {
      x: 7.2, y: py, w: 5.4, h: 0.85,
      fill: { color: i === 2 ? "FFE6E7" : ICE }, line: { color: p.color, width: 1.5 },
      rectRadius: 0.06,
    });
    s.addText(p.id, {
      x: 7.35, y: py + 0.05, w: 5.2, h: 0.4,
      fontFace: FONT_MONO, fontSize: 14, bold: true, color: p.color,
    });
    s.addText(p.payload, {
      x: 7.35, y: py + 0.42, w: 5.2, h: 0.4,
      fontFace: FONT_MONO, fontSize: 14, color: MUTED,
    });
  });

  // Explanation + citation
  s.addText(
    "BEEF fragments reassemble to one UDP datagram; BEF0 overlap is the rewrite vector.",
    {
      x: 7.2, y: 5.9, w: 5.4, h: 0.4,
      fontFace: FONT_BODY, fontSize: 14, italic: true, color: MUTED,
    }
  );
  s.addText("(Ptacek & Newsham, Secure Networks 1998)", {
    x: 7.2, y: 6.25, w: 5.4, h: 0.35,
    fontFace: FONT_BODY, fontSize: 14, color: MUTED, italic: true,
  });

  brandTag(s);
  pageNumber(s, 9, TOTAL);

  s.addNotes(
    "On the left — the actual shaerlock audit output, thirteen findings " +
    "across all four anomaly classes, zero false negatives. All findings " +
    "are INPUT chain — the flawed fixture only has INPUT rules. On the " +
    "right — the fragmentation demo. Two BEEF fragments reassemble into " +
    "one UDP datagram on loopback; the third fragment with id BEF0 is " +
    "the late-arriving overlap that, on a stack which prefers later " +
    "fragments, rewrites the transport header after the filter has " +
    "already let the flow through. That's the SHADOWING evasion in code form."
  );
}

// ============================================================
// Slide 10 — Conclusions
// ============================================================
{
  const s = pres.addSlide();
  darkBg(s);

  s.addText("Conclusions", {
    x: 0.5, y: 0.5, w: 12, h: 0.8,
    fontFace: FONT_TITLE, fontSize: 36, bold: true, color: WHITE,
  });

  const contribs = [
    { n: "1", t: "Detection and explanation are separated.", b: "Deterministic algorithm discovers; LLM only narrates under a JSON contract." },
    { n: "2", t: "Hallucination is a measurable metric.", b: "The eval harness counts invented rule indices — 0 of 13 in our evaluation." },
    { n: "3", t: "Evasion linkage is citation-bound.", b: "Hardcoded MITRE ATT&CK IDs and academic papers; not LLM-fabricated." },
  ];
  contribs.forEach((c, i) => {
    const y = 1.8 + i * 1.6;
    s.addShape("ellipse", {
      x: 0.5, y, w: 0.7, h: 0.7,
      fill: { color: ICE }, line: { color: ICE },
    });
    s.addText(c.n, {
      x: 0.5, y, w: 0.7, h: 0.7,
      fontFace: FONT_TITLE, fontSize: 26, bold: true,
      color: NAVY, align: "center", valign: "middle", margin: 0,
    });
    s.addText(c.t, {
      x: 1.4, y: y - 0.05, w: 11, h: 0.5,
      fontFace: FONT_BODY, fontSize: 20, bold: true, color: WHITE,
      valign: "top",
    });
    s.addText(c.b, {
      x: 1.4, y: y + 0.5, w: 11, h: 0.7,
      fontFace: FONT_BODY, fontSize: 16, color: ICE, italic: true,
      valign: "top",
    });
  });

  // Contact / repo info at the bottom
  s.addShape("rect", {
    x: 0, y: H - 0.9, w: W, h: 0.9,
    fill: { color: NEAR_BLACK }, line: { color: NEAR_BLACK },
  });
  s.addText("github.com/joshuaalwin/shaerlock", {
    x: 0.5, y: H - 0.75, w: 8, h: 0.4,
    fontFace: FONT_MONO, fontSize: 16, color: ICE,
  });
  s.addText("Joshua Alwin · jalwin327@gmail.com", {
    x: W - 6, y: H - 0.75, w: 5.5, h: 0.4,
    fontFace: FONT_BODY, fontSize: 16, color: ICE, align: "right",
  });

  pageNumber(s, 10, TOTAL, true);

  s.addNotes(
    "Three conclusions — separation of detection and explanation; " +
    "hallucination as a measurable quantity; and a citation-bound evasion " +
    "table. This slide stays on screen during Q&A. Code and reproduction " +
    "instructions are at github.com/joshuaalwin/shaerlock."
  );
}

// ============================================================
// Slide 11 — References
// ============================================================
{
  const s = pres.addSlide();
  darkBg(s);

  s.addText("References", {
    x: 0.5, y: 0.5, w: 12, h: 0.8,
    fontFace: FONT_TITLE, fontSize: 36, bold: true, color: WHITE,
  });

  const refs = [
    "[1] T. Ptacek, T. Newsham. Insertion, Evasion, and Denial of Service: Eluding Network Intrusion Detection. Secure Networks Inc., 1998.",
    "[2] E. Al-Shaer, H. Hamed. Discovery of Policy Anomalies in Distributed Firewalls. IEEE INFOCOM 2004.",
    "[3] A. Wool. A Quantitative Study of Firewall Configuration Errors. IEEE Computer 37(6), 2004.",
    "[4] L. Yuan et al. FIREMAN: A Toolkit for Firewall Modeling and Analysis. IEEE S&P 2006.",
    "[5] C. Diekmann et al. Verified iptables Firewall Analysis and Verification. J. Automated Reasoning, 2018.",
    "[6] Y. Lin et al. LLM-Assisted Network Security Policy Audit. arXiv:2407.07930, 2024.",
  ];
  s.addText(
    refs.map((r) => ({ text: r, options: { breakLine: true } })),
    {
      x: 0.5, y: 1.6, w: 12.3, h: 5.0,
      fontFace: FONT_BODY, fontSize: 16, color: ICE,
      paraSpaceAfter: 14, valign: "top",
    }
  );

  pageNumber(s, 11, TOTAL, true);

  s.addNotes(
    "Full references. These are the academic foundations of the project, " +
    "from Ptacek-Newsham 1998 through Lin 2024."
  );
}

pres.writeFile({ fileName: "shaerlock.pptx" })
  .then((p) => console.log("wrote", p))
  .catch((e) => { console.error(e); process.exit(1); });
