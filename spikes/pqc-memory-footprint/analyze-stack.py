#!/usr/bin/env python3
"""
Static worst-case stack bound for one operation.

Reads GCC -fstack-usage (.su) files for per-function frame sizes and the
disassembly of the linked image for the call graph, then reports the maximum
stack depth reachable from an entry symbol.

Non-recursive code only (ML-DSA-44 / ML-KEM-512 reference C and this repo's
fips202 are non-recursive); a cycle is reported as an error.
"""

import argparse
import pathlib
import re
import subprocess
import sys

OBJDUMP = "riscv64-unknown-elf-objdump"


def read_su(build_dir):
    frames = {}
    dynamic = set()
    for su in pathlib.Path(build_dir).glob("*.su"):
        for line in su.read_text().splitlines():
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            name = parts[0].split(":")[-1]
            size = int(parts[1])
            qual = parts[2].strip()
            frames[name] = max(frames.get(name, 0), size)
            if qual != "static":
                dynamic.add(name)
    return frames, dynamic


FUNC_RE = re.compile(r"^[0-9a-f]+ <([^>]+)>:$")
INSN_RE = re.compile(r"^\s*[0-9a-f]+:\s+(.*\S)\s*$")
NAME_RE = re.compile(r"<([^>+]+)(?:\+0x[0-9a-f]+)?>")
HASHNAME_RE = re.compile(r"#\s*[0-9a-f]+\s*<([^>+]+)(?:\+0x[0-9a-f]+)?>")

DIRECT_CALLS = {"jal", "c.jal", "j", "c.j", "call", "tail"}
INDIRECT_CALLS = {"jalr", "c.jalr"}


def read_callgraph(elf):
    out = subprocess.run(
        [OBJDUMP, "-d", "--no-show-raw-insn", elf],
        capture_output=True, text=True, check=True,
    ).stdout
    graph = {}
    indirect = set()
    cur = None
    for line in out.splitlines():
        m = FUNC_RE.match(line)
        if m:
            cur = m.group(1)
            graph.setdefault(cur, set())
            continue
        if cur is None:
            continue
        mi = INSN_RE.match(line)
        if not mi:
            continue
        insn = mi.group(1)
        mnem = re.split(r"[\t ]", insn, maxsplit=1)[0]
        if mnem in DIRECT_CALLS:
            mn = NAME_RE.search(insn)
            if mn and mn.group(1) != cur:
                graph[cur].add(mn.group(1))
        elif mnem in INDIRECT_CALLS:
            mn = HASHNAME_RE.search(insn) or NAME_RE.search(insn)
            if mn:
                if mn.group(1) != cur:
                    graph[cur].add(mn.group(1))
            else:
                indirect.add(cur)
    return graph, indirect


def worst_case(entry, graph, frames):
    best_path = {}

    def visit(fn, stack):
        if fn in stack:
            raise RuntimeError("recursion: " + " -> ".join(list(stack) + [fn]))
        if fn in best_path:
            return best_path[fn]
        own = frames.get(fn, 0)
        deepest, sub = 0, []
        for c in sorted(graph.get(fn, ())):
            cost, path = visit(c, stack | {fn})
            if cost > deepest:
                deepest, sub = cost, path
        result = (own + deepest, [(fn, own)] + sub)
        best_path[fn] = result
        return result

    return visit(entry, set())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build-dir", required=True)
    ap.add_argument("--elf", required=True)
    ap.add_argument("--entry", required=True)
    args = ap.parse_args()

    frames, dynamic = read_su(args.build_dir)
    graph, indirect = read_callgraph(args.elf)

    if args.entry not in graph:
        print(f"error: entry {args.entry!r} not in disassembly", file=sys.stderr)
        return 2

    total, path = worst_case(args.entry, graph, frames)

    reachable = {fn for fn, _ in path}
    missing = sorted(
        c for fn in reachable for c in graph.get(fn, ()) if c not in frames
    )
    bad_indirect = sorted(indirect & reachable)

    print(f"entry: {args.entry}")
    print(f"WORST_CASE_STACK={total}")
    print("deepest path (frame bytes):")
    for fn, sz in path:
        print(f"  {sz:6d}  {fn}")
    if dynamic & reachable:
        print("WARNING dynamic (VLA/alloca) frames:", sorted(dynamic & reachable))
    if bad_indirect:
        print("WARNING indirect calls on path (not followed):", bad_indirect)
    if missing:
        print("note: no .su (frame counted as 0):", ", ".join(sorted(set(missing))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
