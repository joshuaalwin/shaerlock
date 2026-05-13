# slides — ENPM693 final presentation

5-minute, 10-slide PPTX for the `shaerlock` project.

## Layout

| # | Slide | Theme |
|---|-------|-------|
| 1 | Title | dark navy |
| 2 | Problem & motivation | light, two-card |
| 3 | Course angle (AI-as-auditor) | light, big quote |
| 4 | Architecture pipeline | light, 5-stage |
| 5 | Anomaly taxonomy (2×2 grid) | light, set-theory predicates |
| 6 | Evasion linkage table | light, 4-row table |
| 7 | LLM design + hallucination metric | light, code + stat callout |
| 8 | Evaluation results | light, 3 stat cards + severity bar |
| 9 | Demo evidence | light, terminal + fragment diagram |
| 10 | Contributions + references | dark navy, closing |

Speaker notes are embedded on every slide via `slide.addNotes(...)`.

## Build

```bash
cd slides
node build.js          # writes shaerlock.pptx
```

Dependencies (one-time):

```bash
npm install            # installs pptxgenjs locally
```

## Render to images for QA

```bash
soffice --headless --convert-to pdf shaerlock.pptx
pdftoppm -jpeg -r 110 shaerlock.pdf qa/slide
```

Outputs `qa/slide-01.jpg … slide-10.jpg`.

## Content QA

```bash
python -m markitdown shaerlock.pptx | less
python -m markitdown shaerlock.pptx | grep -iE "xxxx|lorem|ipsum|todo|fixme|undefined"
```

## Theme

Midnight Executive palette — primary `#1E2761` navy, secondary `#CADCFC`
ice blue, accent `#F96167` coral, white `#FFFFFF`. Header font Georgia,
body font Calibri, monospace Courier New. All defined as constants at the
top of `build.js`.

## Editing

To change content, edit the inline strings inside each slide block in
`build.js` and rebuild. Each of the 10 slides lives in its own brace
block labeled with a comment header (`// Slide N — ...`).
