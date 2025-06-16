#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 NVIDIA Corporation & Affiliates

import sys
import re
import os

RED = "\033[91m"
RESET = "\033[0m"
ENUM_PATTERN = r'enum\s+rte_mempool_history_op\s*{([^}]+)}'
VALUE_PATTERN = r'([A-Z_]+)\s*=\s*(\d+),\s*(?:/\*\s*(.*?)\s*\*/)?'

def match_field(match: re.Match) -> tuple[int, str]:
    name, value, _ = match.groups()
    return (int(value), name.replace('RTE_MEMPOOL_', ''))

def parse_history_enum(header_file: str) -> dict[int, str]:
    with open(header_file, 'r') as f:
        content = f.read()

    # Extract each enum value and its comment
    enum_content = re.search(ENUM_PATTERN, content, re.DOTALL).group(1)
    return dict(map(match_field, re.finditer(VALUE_PATTERN, enum_content)))


# Generate HISTORY_OPS from the header file
HEADER_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'lib/mempool/rte_mempool.h')
try:
    HISTORY_OPS = parse_history_enum(HEADER_FILE)
except Exception as e:
    print(f"Warning: Could not generate HISTORY_OPS from header file: {e}")


def op_to_string(op: int) -> str:
    return HISTORY_OPS.get(op, f"UNKNOWN({op})")

def parse_mempool_object_history(line: str) -> list[str]:
    line = line.strip().replace('0x', '')
    return [op_to_string(int(digit)) for digit in line]

def parse_metrics(lines: list[str]) -> dict[str, int]:
    metrics = {}
    for line in lines:
        if ':' not in line:
            continue
        key, value = line.split(':', 1)
        metrics[key.strip()] = int(value.strip())
    return metrics

def print_history_sequence(ops: list[str]) -> bool:
    sequence = []
    had_repeat = False
    for idx, op in enumerate(ops):
        if idx > 0 and op == ops[idx-1] and op != 'NEVER':
            sequence.append(RED + op + RESET)
            had_repeat = True
        else:
            sequence.append(op)

    if not sequence:
        return had_repeat

    max_op_width = max(len(re.sub(r'\x1b\[[0-9;]*m', '', op)) for op in sequence)
    OP_WIDTH = max_op_width
    for i in range(0, len(sequence), 4):
        chunk = sequence[i:i+4]
        formatted_ops = [f"{op:<{OP_WIDTH}}" for op in chunk]
        line = ""
        for j, op in enumerate(formatted_ops):
            line += op
            if j < len(formatted_ops) - 1:
                line += " -> "
        if i + 4 < len(sequence):
            line += " ->"
        print("\t" + line)
    return had_repeat

def main():
    if len(sys.argv) != 2:
        print("Usage: {} <history_file>".format(sys.argv[0]))
        sys.exit(1)

    try:
        with open(sys.argv[1], 'r') as f:
            lines = f.readlines()

        # Find where metrics start
        metrics_start = -1
        for i, line in enumerate(lines):
            if "Populated:" in line:
                metrics_start = i
                break

        # Process mempool object history traces
        marked_mempool_objects = []
        mempool_object_id = 1
        for line in lines[:metrics_start] if metrics_start != -1 else lines:
            if not line.strip():
                continue
            ops = parse_mempool_object_history(line)
            print(f"MEMPOOL OBJECT {mempool_object_id}:")
            had_repeat = print_history_sequence(ops)
            print()  # Empty line between mempool objects
            if had_repeat:
                marked_mempool_objects.append(mempool_object_id)
            mempool_object_id += 1

        if marked_mempool_objects:
            print("MEMPOOL OBJECTS with repeated ops:", marked_mempool_objects)

        if metrics_start != -1:
            print("=== Metrics Summary ===")
            metrics = parse_metrics(lines[metrics_start:])
            # Find max width of metric names for alignment
            max_name_width = max(len(name) for name in metrics.keys())
            # Print metrics in aligned format
            for name, value in metrics.items():
                print(f"{name + ':':<{max_name_width + 2}} {value}")

    except FileNotFoundError:
        print(f"Error: File {sys.argv[1]} not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error processing file: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
