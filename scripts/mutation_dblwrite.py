#!/usr/bin/env python3
"""Hand-rolled mutation testing for REQ SVALINN-BEHAVIOR-DBLWRITE-001.

go-mutesting crashes under Go 1.22 (vendored x/tools from 2019 hits a nil
StdSizes in go/types), so each mutant below is applied to the real source, the
package test suite is run, and the mutant is recorded as KILLED (tests fail) or
SURVIVED (tests still pass). The file is always restored.
"""
import subprocess
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
TARGET = ROOT / "internal" / "server" / "middleware.go"

GUARD = """\t\t\tif wrapped.wroteHeader {
\t\t\t\treturn
\t\t\t}
"""

BOOKKEEPING = """\t\t\tatomic.AddInt64(&s.stats.BlockedRequests, 1)
\t\t\tif s.actorTracker != nil {
\t\t\t\ts.actorTracker.AddThreat(s.getClientIP(r), "behavioral_detector", alert.Score)
\t\t\t}
"""

BLOCK_ENTRY = """\t\tif alert.Score >= s.cfg.BehavioralDetect.BlockScoreThreshold {
\t\t\tatomic.AddInt64(&s.stats.BlockedRequests, 1)
"""

WRITE_SET = """\t// net/http implicitly sends a 200 header on the first Write, so any Write
\t// commits the response just as surely as an explicit WriteHeader does.
\trw.wroteHeader = true
"""

WRITEHEADER_SET = """\trw.status = code
\trw.wroteHeader = true
"""

MUTANTS = [
    ("M1 invert guard condition",
     GUARD, "\t\t\tif !wrapped.wroteHeader {\n\t\t\t\treturn\n\t\t\t}\n"),

    ("M2 remove guard entirely (reintroduce the bug)",
     GUARD, ""),

    ("M3 guard never returns (falls through to write)",
     GUARD, "\t\t\tif wrapped.wroteHeader {\n\t\t\t\t_ = wrapped.wroteHeader\n\t\t\t}\n"),

    ("M4 naive fix: use status != 0 instead of wroteHeader",
     GUARD, "\t\t\tif wrapped.status != 0 {\n\t\t\t\treturn\n\t\t\t}\n"),

    ("M5 Write() stops recording commit (implicit 200 missed)",
     WRITE_SET, ""),

    ("M6 WriteHeader() stops recording commit",
     WRITEHEADER_SET, "\trw.status = code\n"),

    ("M7 guard placed before bookkeeping (telemetry lost when committed)",
     BLOCK_ENTRY, BLOCK_ENTRY.replace(
         "{\n", "{\n\t\t\tif wrapped.wroteHeader {\n\t\t\t\treturn\n\t\t\t}\n", 1)),

    ("M8 drop BlockedRequests increment",
     BLOCK_ENTRY, "\t\tif alert.Score >= s.cfg.BehavioralDetect.BlockScoreThreshold {\n"),

    ("M9 drop AddThreat call",
     "\t\t\t\ts.actorTracker.AddThreat(s.getClientIP(r), \"behavioral_detector\", alert.Score)\n", ""),
]


def run_tests():
    r = subprocess.run(
        ["go", "test", "./internal/server/"],
        cwd=ROOT, capture_output=True, text=True)
    return r.returncode == 0


def main():
    original = TARGET.read_text(encoding="utf-8")

    if not run_tests():
        print("BASELINE FAILING - aborting", file=sys.stderr)
        return 1
    print("baseline: PASS\n")

    killed = survived = invalid = 0
    try:
        for name, old, new in MUTANTS:
            if old not in original:
                print(f"[INVALID ] {name}: anchor not found")
                invalid += 1
                continue
            if original.count(old) != 1:
                print(f"[INVALID ] {name}: anchor not unique ({original.count(old)})")
                invalid += 1
                continue

            TARGET.write_text(original.replace(old, new, 1), encoding="utf-8")
            if run_tests():
                print(f"[SURVIVED] {name}")
                survived += 1
            else:
                print(f"[KILLED  ] {name}")
                killed += 1
    finally:
        TARGET.write_text(original, encoding="utf-8")

    total = killed + survived
    score = (killed / total * 100) if total else 0.0
    print(f"\nkilled={killed} survived={survived} invalid={invalid}")
    print(f"mutation score: {score:.1f}%")

    print("\nrestored; verifying baseline again...")
    print("baseline after restore:", "PASS" if run_tests() else "FAIL")
    return 0


if __name__ == "__main__":
    sys.exit(main())
