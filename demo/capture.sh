#!/usr/bin/env bash
# capture.sh — one-shot reproduction script for the fragmentation demo.
#
# Runs the scapy fragment generator under tcpdump on the loopback interface
# and writes a pcap that opens cleanly in Wireshark.
#
# Usage:
#   sudo ./demo/capture.sh                  # writes demo/frag.pcap
#   sudo PCAP=/tmp/x.pcap ./demo/capture.sh # custom output path

set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "must run as root (raw sockets + tcpdump)" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_PY="${ROOT}/.venv/bin/python"
PCAP="${PCAP:-${ROOT}/demo/frag.pcap}"

if [[ ! -x "${VENV_PY}" ]]; then
  echo "virtualenv missing at ${VENV_PY} — run: python -m venv .venv && pip install -e '.[dev]'" >&2
  exit 1
fi

mkdir -p "$(dirname "${PCAP}")"

echo "[capture.sh] running fragmentation demo, pcap=${PCAP}"
"${VENV_PY}" -m ai_fw_audit.cli demo --pcap "${PCAP}"

echo "[capture.sh] pcap ready. Open with:  wireshark ${PCAP}"
