#!/usr/bin/env python3
"""Hand-rolled mutation testing for REQ SVALINN-CLIENTIP-SPOOF-001.

go-mutesting does not run on this toolchain (Go 1.22), so the mutants for
trustedClientIP are applied literally: each entry rewrites the real source,
runs the REQ test set, and is expected to FAIL (be "killed"). A mutant that
still passes is a survivor -- a behaviour the tests do not actually pin.

Usage: python3 scripts/mutation_clientip.py
"""

import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TARGET = REPO / "internal" / "server" / "server.go"
BACKUP = REPO / "internal" / "server" / "server.go.mutation_backup"

TESTS = "TestGetClientIP|TestWAFMiddleware|TestSQLiProbe|TestServeHTTP_Ecosystem|TestEcosystem"

# (name, original_fragment, mutated_fragment)
MUTANTS = [
    (
        "M1: trust FIRST XFF element (the original vulnerability)",
        "if last := strings.TrimSpace(parts[len(parts)-1]); net.ParseIP(last) != nil {",
        "if last := strings.TrimSpace(parts[0]); net.ParseIP(last) != nil {",
    ),
    (
        "M2: drop the loopback guard (trust headers from any peer)",
        "\tif !isLoopbackIP(remoteIP) {\n\t\treturn remoteIP\n\t}\n",
        "",
    ),
    (
        "M3: invert the loopback guard",
        "if !isLoopbackIP(remoteIP) {",
        "if isLoopbackIP(remoteIP) && false {",
    ),
    (
        "M4: ignore X-Real-IP entirely",
        'if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); net.ParseIP(xri) != nil {\n\t\treturn xri\n\t}\n',
        "",
    ),
    (
        "M5: accept an unparseable X-Real-IP",
        'if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); net.ParseIP(xri) != nil {',
        'if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {',
    ),
    (
        "M6: accept an unparseable XFF element",
        "if last := strings.TrimSpace(parts[len(parts)-1]); net.ParseIP(last) != nil {",
        'if last := strings.TrimSpace(parts[len(parts)-1]); last != "" {',
    ),
    (
        "M7: drop the portless-RemoteAddr fallback",
        "\tif err != nil {\n\t\tremoteIP = r.RemoteAddr\n\t}\n",
        "",
    ),
    (
        "M8: stop trimming the XFF element",
        "if last := strings.TrimSpace(parts[len(parts)-1]); net.ParseIP(last) != nil {",
        "if last := parts[len(parts)-1]; net.ParseIP(last) != nil {",
    ),
    (
        "M9: stop trimming X-Real-IP",
        'if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); net.ParseIP(xri) != nil {',
        'if xri := r.Header.Get("X-Real-IP"); net.ParseIP(xri) != nil {',
    ),
    (
        "M10: ignore X-Forwarded-For entirely",
        '\tif xff := r.Header.Get("X-Forwarded-For"); xff != "" {',
        '\tif xff := r.Header.Get("X-Forwarded-For"); false {',
    ),
    (
        "M11: ecosystem resolver diverges back to the old first-element logic",
        "func (s *Server) ecosystemClientIP(r *http.Request) string {\n\treturn trustedClientIP(r)\n}",
        'func (s *Server) ecosystemClientIP(r *http.Request) string {\n\tif xff := r.Header.Get("X-Forwarded-For"); xff != "" {\n\t\treturn strings.TrimSpace(strings.Split(xff, ",")[0])\n\t}\n\treturn trustedClientIP(r)\n}',
    ),
]


def run_tests() -> bool:
    """Return True if the REQ test set passes."""
    proc = subprocess.run(
        ["wsl", "-e", "bash", "-c",
         f"cd your-project-root && go test -count=1 -run '{TESTS}' ./internal/server/..."],
        capture_output=True, text=True,
    )
    return proc.returncode == 0


def main() -> int:
    original = TARGET.read_text(encoding="utf-8")
    shutil.copy2(TARGET, BACKUP)

    killed, survived = [], []
    try:
        # Sanity: the unmutated tree must be green, or every "kill" is meaningless.
        if not run_tests():
            print("ABORT: baseline test set is not green before mutation")
            return 2
        print("baseline green\n")

        for name, old, new in MUTANTS:
            if old not in original:
                print(f"ERROR  {name}\n       fragment not found -- mutant not applied")
                return 2

            TARGET.write_text(original.replace(old, new, 1), encoding="utf-8")
            if run_tests():
                survived.append(name)
                print(f"SURVIVED  {name}")
            else:
                killed.append(name)
                print(f"killed    {name}")
    finally:
        shutil.copy2(BACKUP, TARGET)
        BACKUP.unlink(missing_ok=True)

    total = len(MUTANTS)
    print(f"\nmutation score: {len(killed)}/{total} = {100.0 * len(killed) / total:.1f}%")
    for s in survived:
        print(f"  survivor: {s}")
    return 0 if not survived else 1


if __name__ == "__main__":
    sys.exit(main())
