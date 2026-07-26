//! Generate a CycloneDX 1.5 software bill of materials from the repository's own
//! pinned manifests (#5).
//!
//! Every dependency this build resolves is pinned twice — Zig packages by content
//! hash in `build.zig.zon`, system packages by version in `pantry.lock` — and the
//! SBOM is produced from those files rather than from an environment scan. That
//! matters: a scan reports what happened to be installed on the machine that ran it,
//! while the manifests are what the build is defined to use. An SBOM that disagrees
//! with the build is worse than none, because it is trusted.
//!
//! Usage: `zig build sbom > sbom.json`

const std = @import("std");

const ZonDependency = struct {
    url: []const u8,
    hash: []const u8,
};

const ZonManifest = struct {
    name: enum { waf },
    version: []const u8,
    minimum_zig_version: []const u8,
    fingerprint: u64,
    dependencies: struct {
        injection: ZonDependency,
        regex: ZonDependency,
        xml: ZonDependency,
    },
    paths: []const []const u8,
};

/// A lockfile entry. `resolved` names a registry coordinate; entries installed
/// straight from Pantry carry `source` instead, so both are optional and one of them
/// is required — a package with neither is a lockfile this tool does not understand,
/// and it says so rather than leaving the component out.
const LockPackage = struct {
    name: []const u8,
    version: []const u8,
    resolved: ?[]const u8 = null,
    source: ?[]const u8 = null,
};

pub fn main(init: std.process.Init) !void {
    var arena_state = std.heap.ArenaAllocator.init(init.gpa);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    var arguments = std.process.Args.Iterator.init(init.minimal.args);
    _ = arguments.next();
    const manifest_path = arguments.next() orelse "build.zig.zon";
    const lock_path = arguments.next() orelse "pantry.lock";
    // The timestamp is passed in rather than read from the clock: an SBOM that
    // changes on every run cannot be compared between builds, and reproducibility is
    // the property this file exists to support.
    const timestamp = arguments.next() orelse "1970-01-01T00:00:00Z";

    const manifest_bytes = try std.Io.Dir.cwd().readFileAllocOptions(
        init.io,
        manifest_path,
        allocator,
        .limited(1024 * 1024),
        .of(u8),
        0,
    );
    const manifest = try std.zon.parse.fromSliceAlloc(ZonManifest, allocator, manifest_bytes, null, .{ .ignore_unknown_fields = true });

    const lock_bytes = try std.Io.Dir.cwd().readFileAlloc(init.io, lock_path, allocator, .limited(4 * 1024 * 1024));
    var lock = try std.json.parseFromSlice(std.json.Value, allocator, lock_bytes, .{});
    defer lock.deinit();

    var out: std.ArrayList(u8) = .empty;
    try out.print(allocator,
        \\{{
        \\  "bomFormat": "CycloneDX",
        \\  "specVersion": "1.5",
        \\  "version": 1,
        \\  "metadata": {{
        \\    "timestamp": "{s}",
        \\    "component": {{
        \\      "type": "library",
        \\      "name": "zig-waf",
        \\      "version": "{s}",
        \\      "description": "Zig WAF engine"
        \\    }},
        \\    "tools": [{{ "name": "zig-waf sbom", "version": "{s}" }}]
        \\  }},
        \\  "components": [
        \\
    , .{ timestamp, manifest.version, manifest.version });

    var first = true;
    // Zig packages, pinned by content hash: the hash is the identity, so it is the
    // component's version *and* its recorded checksum.
    inline for (.{
        .{ "zig-injection", manifest.dependencies.injection },
        .{ "zig-regex", manifest.dependencies.regex },
        .{ "zig-xml", manifest.dependencies.xml },
    }) |entry| {
        try appendComponent(&out, allocator, &first, .{
            .name = entry[0],
            .version = entry[1].hash,
            .purl_type = "zig",
            .reference = entry[1].url,
        });
    }

    // System packages from the Pantry lockfile, pinned by resolved version.
    if (lock.value.object.get("packages")) |packages| {
        var it = packages.object.iterator();
        while (it.next()) |package| {
            // A malformed entry fails the run. Skipping it would produce an SBOM
            // that silently omits a dependency, and a bill of materials with a
            // missing line is worse than no bill at all, because it is trusted.
            const parsed = std.json.parseFromValue(LockPackage, allocator, package.value_ptr.*, .{
                .ignore_unknown_fields = true,
            }) catch return error.UnrecognizedLockEntry;
            try appendComponent(&out, allocator, &first, .{
                .name = parsed.value.name,
                .version = parsed.value.version,
                .purl_type = "generic",
                .reference = parsed.value.resolved orelse parsed.value.source orelse return error.LockEntryHasNoOrigin,
            });
        }
    }

    try out.print(allocator,
        \\
        \\  ]
        \\}}
        \\
    , .{});
    var stdout_buffer: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(init.io, &stdout_buffer);
    try stdout.interface.writeAll(out.items);
    try stdout.interface.flush();
}

const Component = struct {
    name: []const u8,
    version: []const u8,
    purl_type: []const u8,
    reference: []const u8,
};

fn appendComponent(out: *std.ArrayList(u8), allocator: std.mem.Allocator, first: *bool, component: Component) !void {
    if (!first.*) try out.appendSlice(allocator, ",\n");
    first.* = false;
    try out.print(allocator,
        \\    {{
        \\      "type": "library",
        \\      "name": "{s}",
        \\      "version": "{s}",
        \\      "purl": "pkg:{s}/{s}@{s}",
        \\      "externalReferences": [{{ "type": "distribution", "url": "{s}" }}]
        \\    }}
    , .{ component.name, component.version, component.purl_type, component.name, component.version, component.reference });
}
