"""Standalone wrapper around the in-package fragmentation demo runner.

Useful when you want to invoke the demo without going through the typer CLI
(e.g. inside a tcpdump capture script). Equivalent to:

    sudo .venv/bin/python -m ai_fw_audit.cli demo

but as a single small file you can hand-edit during a presentation.

Usage (from project root, with .venv active):
    sudo .venv/bin/python demo/frag_demo.py [--port 8080] [--pcap demo/frag.pcap]
"""

from __future__ import annotations

import argparse
from pathlib import Path

from rich.console import Console

from ai_fw_audit.demo_runner import run_fragmentation_demo


def main() -> None:
    p = argparse.ArgumentParser(description="Fragmentation evasion demo (loopback only).")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--pcap", type=Path, default=Path("demo/frag.pcap"))
    p.add_argument("--no-capture", action="store_true")
    p.add_argument("--overlap-only", action="store_true")
    args = p.parse_args()

    run_fragmentation_demo(
        target_port=args.port,
        pcap_out=args.pcap,
        no_capture=args.no_capture,
        overlap_only=args.overlap_only,
        console=Console(),
    )


if __name__ == "__main__":
    main()
