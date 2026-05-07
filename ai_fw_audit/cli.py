"""shaerlock CLI (typer-based)."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .analyzer import analyze, skipped_rules
from .enricher import enrich
from .evasion import map_finding
from .llm.base import get_provider
from .parser import parse_iptables_save
from .schemas import Severity

app = typer.Typer(
    name="shaerlock",
    help="An iptables policy detective. Deterministic discovery, LLM-narrated findings, evasion linkage. UMD ENPM693 final project.",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()


SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "dim",
}


def _bootstrap_env():
    """Load .env from CWD if present (gitignored, never committed)."""
    load_dotenv(dotenv_path=Path.cwd() / ".env", override=False)


@app.command()
def audit(
    ruleset: Path = typer.Argument(..., exists=True, readable=True, help="iptables-save text file"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Run deterministic analysis only"),
    provider: str = typer.Option(
        "auto", "--provider", help="LLM provider: auto|ollama|anthropic|none"
    ),
    json_out: Path | None = typer.Option(None, "--json", help="Also write findings as JSON"),
):
    """Audit a firewall ruleset for misconfigurations."""
    _bootstrap_env()

    text = ruleset.read_text()
    chains = parse_iptables_save(text)
    rule_count = sum(len(rs) for rs in chains.values())

    console.print(
        Panel.fit(
            f"[bold]ruleset:[/] {ruleset}\n"
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
        st.add_column("chain"); st.add_column("idx", justify="right")
        st.add_column("reason"); st.add_column("rule", overflow="fold")
        for r in skipped:
            reason = []
            if r.has_state_match: reason.append("stateful match")
            if r.has_negation: reason.append("negation")
            if r.has_unhandled_match: reason.append("unhandled match module")
            if r.in_iface == "lo" or r.out_iface == "lo": reason.append("loopback")
            st.add_row(r.chain, str(r.chain_idx), ", ".join(reason) or "(unspecified)", r.raw)
        console.print(st)

    if not findings:
        console.print("[green]no anomalies detected[/]")
        return

    if no_llm or provider == "none":
        _render_findings(findings)
        if json_out:
            payload = []
            for f in findings:
                m = map_finding(f)
                payload.append(
                    {
                        "finding": f.model_dump(mode="json"),
                        "evasion": {
                            "technique": m.technique,
                            "mitre_attck_id": m.mitre_attck_id,
                            "mitre_attck_name": m.mitre_attck_name,
                            "citation": m.citation,
                            "narrative": m.narrative,
                        },
                    }
                )
            json_out.write_text(json.dumps(payload, indent=2))
            console.print(f"[dim]wrote {json_out}[/]")
        return

    p = get_provider(provider)
    if p is None:
        console.print(
            "[yellow]no LLM provider available "
            "(no Ollama at localhost:11434 and ANTHROPIC_API_KEY not set). "
            "Falling back to --no-llm output.[/]"
        )
        _render_findings(findings)
        return

    console.print(f"[dim]enriching {len(findings)} finding(s) via provider={p.name}...[/]")
    enriched = enrich(findings, p)
    _render_enriched(enriched)
    if json_out:
        json_out.write_text(
            json.dumps([e.model_dump(mode="json") for e in enriched], indent=2)
        )
        console.print(f"[dim]wrote {json_out}[/]")


def _render_findings(findings):
    t = Table(title=f"Anomalies ({len(findings)}) — deterministic only", show_lines=False, header_style="bold")
    t.add_column("class", style="bold")
    t.add_column("chain"); t.add_column("primary", justify="right")
    t.add_column("secondary", justify="right"); t.add_column("explanation", overflow="fold")
    t.add_column("evasion (MITRE)", overflow="fold")
    for f in findings:
        m = map_finding(f)
        t.add_row(
            f.anomaly_class.value,
            f.chain,
            str(f.primary_idx),
            str(f.secondary_idx),
            f.explanation,
            f"{m.technique} [dim]({m.mitre_attck_id} {m.mitre_attck_name})[/]",
        )
    console.print(t)


def _render_enriched(enriched):
    t = Table(title=f"Anomalies ({len(enriched)}) — LLM-enriched + evasion-linked", show_lines=True, header_style="bold")
    t.add_column("class", style="bold"); t.add_column("severity")
    t.add_column("chain"); t.add_column("idx"); t.add_column("explanation", overflow="fold")
    t.add_column("suggested fix", overflow="fold")
    t.add_column("evasion (MITRE)", overflow="fold")
    t.add_column("provider", style="dim")
    for e in enriched:
        f = e.finding
        sev_style = SEVERITY_STYLE.get(e.severity, "")
        evasion_cell = (
            f"{e.evasion_technique} [dim]({e.evasion_attck_id})[/]"
            if e.evasion_technique
            else "[dim]—[/]"
        )
        t.add_row(
            f.anomaly_class.value,
            f"[{sev_style}]{e.severity.value}[/]",
            f.chain,
            f"{f.primary_idx} ↔ {f.secondary_idx}",
            e.explanation,
            e.suggested_fix,
            evasion_cell,
            e.provider,
        )
    console.print(t)


@app.command()
def evaluate(
    ruleset: Path = typer.Argument(..., exists=True, readable=True),
    answers: Path = typer.Argument(..., exists=True, readable=True, help="ANSWERS.md ground truth"),
    provider: str = typer.Option("auto", "--provider"),
    out: Path | None = typer.Option(None, "--out", help="Write evaluation JSON"),
):
    """Grade the LLM enrichment against an ANSWERS.md ground-truth file."""
    _bootstrap_env()
    from .evaluation import grade_against_answers
    grade_against_answers(ruleset, answers, provider=provider, out=out)


@app.command()
def configure(
    delete: bool = typer.Option(False, "--delete", help="Delete the stored key instead of setting it"),
):
    """Store the Anthropic API key in the OS keyring (encrypted at rest).

    The key is read via getpass — it does not echo to the terminal and is not
    written to shell history or any file on disk.
    """
    import getpass

    from .secrets import delete_secret, get_secret, set_secret

    if delete:
        msg = delete_secret("ANTHROPIC_API_KEY")
        console.print(f"[dim]{msg}[/]")
        return

    existing = get_secret("ANTHROPIC_API_KEY")
    if existing:
        console.print("[yellow]An ANTHROPIC_API_KEY is already configured.[/]")
        confirm = typer.confirm("Overwrite?", default=False)
        if not confirm:
            return

    key = getpass.getpass("Anthropic API key (input hidden): ").strip()
    if not key:
        console.print("[red]empty input — aborted.[/]")
        raise typer.Exit(code=1)
    if not key.startswith("sk-ant-"):
        console.print("[yellow]warning: key does not start with 'sk-ant-'; storing anyway.[/]")

    msg = set_secret("ANTHROPIC_API_KEY", key)
    console.print(f"[green]ok[/] — {msg}")
    console.print(
        "[dim]verify with:[/] [bold]shaerlock audit tests/fixtures/flawed-ruleset.txt --provider anthropic[/]"
    )


@app.command()
def demo(
    target_port: int = typer.Option(8080, "--port", help="Localhost port the listener will bind to"),
    pcap_out: Path = typer.Option(Path("demo/frag.pcap"), "--pcap", help="Where to write the capture"),
    no_capture: bool = typer.Option(False, "--no-capture", help="Skip the tcpdump capture step"),
    overlap_only: bool = typer.Option(False, "--overlap-only", help="Send only the overlap pair, skip listener"),
):
    """Run the IPv4-fragmentation evasion demo on the loopback interface.

    Visualizes the SHADOWING → fragmentation evasion link by emitting a pair
    of overlapping IPv4 fragments to localhost and capturing them with
    tcpdump. The pcap is then loadable in Wireshark for the writeup.

    Requires root for raw sockets and tcpdump (use sudo).
    """
    from .demo_runner import run_fragmentation_demo

    run_fragmentation_demo(
        target_port=target_port,
        pcap_out=pcap_out,
        no_capture=no_capture,
        overlap_only=overlap_only,
        console=console,
    )


if __name__ == "__main__":
    app()
