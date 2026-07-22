#!/usr/bin/env python3
"""Generate the immutable Zig HTML5 entity table used by Coraza parity."""

from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path


GO_1_25_ENTITY_SHA256 = "4e6dd013ad9d909f4f8a93d200567c5fd88a2cc1d12b1c2046b3fd199b373ec1"
SINGLE = re.compile(r'^\s*"([^"]+)":\s+\'\\[uU]([0-9A-Fa-f]+)\',\s*$')
DOUBLE = re.compile(
    r'^\s*"([^"]+)":\s+\{\'\\[uU]([0-9A-Fa-f]+)\',\s+\'\\[uU]([0-9A-Fa-f]+)\'\},\s*$'
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path, help="Go 1.25 src/html/entity.go")
    parser.add_argument("output", type=Path, help="generated Zig output")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    source = args.source.read_bytes()
    digest = hashlib.sha256(source).hexdigest()
    if digest != GO_1_25_ENTITY_SHA256:
        raise SystemExit(f"unexpected entity.go SHA-256: {digest}")

    entries: dict[str, tuple[int, int | None]] = {}
    for line in source.decode().splitlines():
        if match := SINGLE.match(line):
            entries[match.group(1)] = (int(match.group(2), 16), None)
        elif match := DOUBLE.match(line):
            entries[match.group(1)] = (int(match.group(2), 16), int(match.group(3), 16))

    if len(entries) != 2229:
        raise SystemExit(f"expected 2229 HTML5 entity names, found {len(entries)}")

    lines = [
        "//! Generated from Go 1.25 src/html/entity.go; DO NOT EDIT.",
        "// Copyright 2010 The Go Authors. All rights reserved.",
        "// Use of this source code is governed by a BSD-style license.",
        f"// Source SHA-256: {digest}",
        "",
        'const std = @import("std");',
        "",
        "pub const Value = struct { first: u21, second: ?u21 = null };",
        "const Entry = struct { name: []const u8, value: Value };",
        "",
        "const entries = [_]Entry{",
    ]
    for name, (first, second) in sorted(entries.items()):
        suffix = "" if second is None else f", .second = 0x{second:x}"
        lines.append(f'    .{{ .name = "{name}", .value = .{{ .first = 0x{first:x}{suffix} }} }},')
    lines.extend(
        [
            "};",
            "",
            "pub fn lookup(name: []const u8) ?Value {",
            "    var low: usize = 0;",
            "    var high: usize = entries.len;",
            "    while (low < high) {",
            "        const middle = low + (high - low) / 2;",
            "        switch (std.mem.order(u8, name, entries[middle].name)) {",
            "            .lt => high = middle,",
            "            .gt => low = middle + 1,",
            "            .eq => return entries[middle].value,",
            "        }",
            "    }",
            "    return null;",
            "}",
            "",
            'test "generated table contains single and paired HTML5 entities" {',
            '    try std.testing.expectEqual(@as(u21, 0x26), lookup("amp;").?.first);',
            '    try std.testing.expectEqual(@as(u21, 0x3c), lookup("nvlt;").?.first);',
            '    try std.testing.expectEqual(@as(?u21, 0x20d2), lookup("nvlt;").?.second);',
            '    try std.testing.expect(lookup("not-an-entity;") == null);',
            "}",
            "",
        ]
    )
    args.output.write_text("\n".join(lines))


if __name__ == "__main__":
    main()
