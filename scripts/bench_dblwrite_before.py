#!/usr/bin/env python3
"""Phase 7 'before' measurement for REQ SVALINN-BEHAVIOR-DBLWRITE-001.

The repo has no git, so the pre-fix source is reconstructed in place, benchmarked,
and then restored. Only the benchmarks run (-run '^$'), so the tests that the
pre-fix code would fail do not interfere.
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

POST_STRUCT = """type responseWriter struct {
\thttp.ResponseWriter
\tstatus      int
\tbytes       int
\twroteHeader bool
}

func (rw *responseWriter) WriteHeader(code int) {
\trw.status = code
\trw.wroteHeader = true
\trw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
\t// net/http implicitly sends a 200 header on the first Write, so any Write
\t// commits the response just as surely as an explicit WriteHeader does.
\trw.wroteHeader = true
\tn, err := rw.ResponseWriter.Write(b)
\trw.bytes += n
\treturn n, err
}"""

PRE_STRUCT = """type responseWriter struct {
\thttp.ResponseWriter
\tstatus int
\tbytes  int
}

func (rw *responseWriter) WriteHeader(code int) {
\trw.status = code
\trw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
\tn, err := rw.ResponseWriter.Write(b)
\trw.bytes += n
\treturn n, err
}"""

BENCHES = ("BenchmarkResponseWriterWrite|"
           "BenchmarkBehavioralDetectorMiddleware_Passthrough")


def bench():
    r = subprocess.run(
        ["go", "test", "-run=^$", f"-bench={BENCHES}", "-benchmem", "-count=5",
         "./internal/server/"],
        cwd=ROOT, capture_output=True, text=True)
    for line in (r.stdout + r.stderr).splitlines():
        if line.startswith("Benchmark") or "FAIL" in line:
            print(line)
    return r.returncode == 0


def main():
    original = TARGET.read_text(encoding="utf-8")
    for anchor in (GUARD, POST_STRUCT):
        if original.count(anchor) != 1:
            print(f"anchor not unique/found: {anchor[:40]!r}", file=sys.stderr)
            return 1

    prefix = original.replace(GUARD, "", 1).replace(POST_STRUCT, PRE_STRUCT, 1)

    print("=== BEFORE (pre-fix source reconstructed) ===")
    try:
        TARGET.write_text(prefix, encoding="utf-8")
        ok = bench()
    finally:
        TARGET.write_text(original, encoding="utf-8")
    print("restored:", TARGET.read_text(encoding="utf-8") == original)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
