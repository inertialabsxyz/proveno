#!/usr/bin/env python3
"""Trace token benchmark: proveno vs OpenAI function-calling format.

For equivalent tool-calling tasks, compares the token cost of what gets
fed back into the model context after execution:

  proveno:   compact trace  — script + transcript (args + status + byte count, no response bodies)
  OpenAI: full trace     — assistant tool_call messages + tool result messages with full response bodies

Tokenized with cl100k_base (GPT-4 / tiktoken).

Usage:
    pip install tiktoken
    python bench/run.py
    python bench/run.py --json
"""

import argparse
import json
import sys
from pathlib import Path

import tiktoken

TOKENIZER = "cl100k_base"
BENCH_DIR = Path(__file__).parent
TASKS_DIR = BENCH_DIR / "tasks"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--json", dest="emit_json", action="store_true", help="Emit JSON to stdout instead of a table")
    args = parser.parse_args()

    enc = tiktoken.get_encoding(TOKENIZER)

    tasks = sorted(p for p in TASKS_DIR.iterdir() if p.is_dir())
    results = []
    for task_dir in tasks:
        proveno_text   = (task_dir / "trace_proveno.json").read_text()
        openai_text = (task_dir / "trace_openai.json").read_text()
        proveno_tokens   = len(enc.encode(proveno_text))
        openai_tokens = len(enc.encode(openai_text))
        results.append({
            "task": task_dir.name,
            "proveno": proveno_tokens,
            "openai": openai_tokens,
            "ratio": round(proveno_tokens / openai_tokens, 3),
        })

    if args.emit_json:
        json.dump(results, sys.stdout, indent=2)
        print()
        return

    col_task  = 22
    col_num   = 14
    col_ratio = 16
    header = f"{'Task':<{col_task}} {'proveno tokens':>{col_num}} {'OpenAI tokens':>{col_num}} {'Ratio (proveno/OAI)':>{col_ratio}}"
    sep = "-" * len(header)
    print(header)
    print(sep)
    total_proveno = total_openai = 0
    for r in results:
        print(f"{r['task']:<{col_task}} {r['proveno']:>{col_num}} {r['openai']:>{col_num}} {r['ratio']:>{col_ratio}.3f}")
        total_proveno   += r["proveno"]
        total_openai += r["openai"]
    print(sep)
    total_ratio = round(total_proveno / total_openai, 3)
    print(f"{'Total':<{col_task}} {total_proveno:>{col_num}} {total_openai:>{col_num}} {total_ratio:>{col_ratio}.3f}")


if __name__ == "__main__":
    main()
