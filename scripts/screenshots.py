"""Generate SVG screenshots of shaerlock CLI output for README / docs."""

from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ai_fw_audit.analyzer import analyze, skipped_rules
from ai_fw_audit.evasion import map_finding
from ai_fw_audit.parser import parse_iptables_save
from ai_fw_audit.schemas import Severity

ROOT = Path(__file__).resolve().parent.parent
FLAWED = ROOT / "tests" / "fixtures" / "flawed-ruleset.txt"
CLEAN = ROOT / "tests" / "fixtures" / "clean-ruleset.txt"
OUT = ROOT / "docs" / "img"

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "dim",
}


def capture_audit(ruleset_path: Path, output_name: str):
    console = Console(record=True, width=110)

    text = ruleset_path.read_text()
    chains = parse_iptables_save(text)
    rule_count = sum(len(rs) for rs in chains.values())

    console.print(
        Panel.fit(
            f"[bold]ruleset:[/] {ruleset_path.name}\n"
            f"[bold]chains:[/] {', '.join(chains.keys()) or '(none)'}\n"
            f"[bold]rules:[/] {rule_count}",
            title="shaerlock",
            border_style="cyan",
        )
    )

    findings = analyze(chains)
    skipped = skipped_rules(chains)

    if skipped:
        st = Table(title="Rules excluded from pairwise analysis", show_header=True, header_style="dim")
        st.add_column("chain")
        st.add_column("idx", justify="right")
        st.add_column("reason")
        st.add_column("rule", overflow="fold")
        for r in skipped:
            reason = []
            if r.has_state_match:
                reason.append("stateful match")
            if r.has_negation:
                reason.append("negation")
            if r.has_unhandled_match:
                reason.append("unhandled match module")
            if r.in_iface == "lo" or r.out_iface == "lo":
                reason.append("loopback")
            st.add_row(r.chain, str(r.chain_idx), ", ".join(reason) or "(unspecified)", r.raw)
        console.print(st)

    if not findings:
        console.print("[green]no anomalies detected[/]")
    else:
        t = Table(title=f"Anomalies ({len(findings)}) — deterministic only", show_lines=False, header_style="bold")
        t.add_column("class", style="bold")
        t.add_column("chain")
        t.add_column("primary", justify="right")
        t.add_column("secondary", justify="right")
        t.add_column("explanation", overflow="fold", max_width=40)
        t.add_column("evasion (MITRE)", overflow="fold", max_width=30)
        for f in findings:
            m = map_finding(f)
            t.add_row(
                f.anomaly_class.value,
                f.chain,
                str(f.primary_idx),
                str(f.secondary_idx),
                f.explanation,
                f"{m.technique} ({m.mitre_attck_id})",
            )
        console.print(t)

    svg = console.export_svg(title="shaerlock")
    (OUT / f"{output_name}.svg").write_text(svg)
    print(f"wrote {OUT / output_name}.svg")


def capture_eval():
    from ai_fw_audit.evaluation import parse_answers, _findings_as_set

    console = Console(record=True, width=80)

    ruleset = FLAWED
    answers = ROOT / "tests" / "fixtures" / "flawed-ruleset.ANSWERS.md"

    chains = parse_iptables_save(ruleset.read_text())
    findings = analyze(chains)
    planted = parse_answers(answers)
    found = _findings_as_set(findings)

    tp = planted & found
    fp = found - planted
    fn = planted - found

    recall = len(tp) / len(planted) if planted else 0.0
    precision = len(tp) / len(found) if found else 0.0

    t = Table(title="Deterministic vs ground truth", header_style="bold")
    t.add_column("metric")
    t.add_column("value", justify="right")
    for k, v in [
        ("planted", len(planted)),
        ("found", len(found)),
        ("true_positive", len(tp)),
        ("false_positive", len(fp)),
        ("false_negative", len(fn)),
        ("recall", round(recall, 3)),
        ("precision", round(precision, 3)),
    ]:
        t.add_row(k, str(v))
    console.print(t)

    svg = console.export_svg(title="shaerlock evaluate")
    (OUT / "eval.svg").write_text(svg)
    print(f"wrote {OUT / 'eval.svg'}")


def capture_help():
    import subprocess
    result = subprocess.run(
        ["python", "-m", "ai_fw_audit.cli", "--help"],
        capture_output=True, text=True, cwd=ROOT,
    )
    console = Console(record=True, width=90)
    console.print(result.stdout)
    svg = console.export_svg(title="shaerlock --help")
    (OUT / "help.svg").write_text(svg)
    print(f"wrote {OUT / 'help.svg'}")


if __name__ == "__main__":
    capture_audit(FLAWED, "audit-flawed")
    capture_audit(CLEAN, "audit-clean")
    capture_eval()
    capture_help()
