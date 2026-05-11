//! Atomic Red Team adapter — translate an ART atomic-test YAML descriptor
//! into the internal TTP shape that `runCmd` already consumes.
//!
//! ART schema we read (subset):
//!   attack_technique: T1082
//!   display_name: System Information Discovery
//!   atomic_tests:
//!     - name: <test-name>
//!       description: <text>
//!       supported_platforms: [linux, macos, windows]
//!       input_arguments:
//!         <var>: { description: ..., type: ..., default: <value> }
//!       executor:
//!         command: <multi-line shell>
//!         name: bash | sh | command_prompt | powershell
//!         elevation_required: bool
//!
//! v0.3 limitations (called out in the README's experimental tag):
//!   - Only `bash` and `sh` executors are run as-is. Other executors
//!     (powershell, command_prompt) are surfaced but not adapted; the
//!     adapter rejects them rather than silently mis-running.
//!   - `input_arguments` substitution: `#{var}` placeholders in the
//!     command are replaced with the variable's `default`. If a
//!     variable has no default, the substitution is left literal —
//!     bash will see `#{var}` and probably error, which is the right
//!     fail-loud behavior.
//!   - `cleanup_command` is ignored (the runner doesn't have a cleanup
//!     hook today).
//!   - `dependencies` / `dependency_executor_name` are ignored. Any
//!     atomic that requires dependencies will likely fail at run time;
//!     v0.4 plans a `--check-deps` mode.

const std = @import("std");
const yaml = @import("yaml.zig");

pub const Adapted = struct {
    id: []const u8,
    name: []const u8,
    description: []const u8,
    platforms: []const []const u8,
    exec: []const u8,
};

pub const AdaptError = error{
    NotAnArtAtomic,
    NoAtomicTests,
    AtomicTestNotFound,
    UnsupportedExecutor,
    OutOfMemory,
};

pub const Selector = union(enum) {
    /// Select first atomic test (default).
    first,
    /// Select by 0-based index.
    index: usize,
    /// Select by exact `name` match.
    name: []const u8,
};

pub fn adapt(
    arena: std.mem.Allocator,
    root: yaml.Node,
    selector: Selector,
) AdaptError!Adapted {
    if (root != .mapping) return error.NotAnArtAtomic;

    const technique = root.lookup("attack_technique") orelse return error.NotAnArtAtomic;
    const technique_id = technique.asString() orelse return error.NotAnArtAtomic;

    const atomics = root.lookup("atomic_tests") orelse return error.NoAtomicTests;
    if (atomics != .sequence) return error.NoAtomicTests;
    if (atomics.sequence.len == 0) return error.NoAtomicTests;

    const test_node = switch (selector) {
        .first => atomics.sequence[0],
        .index => |i| blk: {
            if (i >= atomics.sequence.len) return error.AtomicTestNotFound;
            break :blk atomics.sequence[i];
        },
        .name => |wanted| blk: {
            for (atomics.sequence) |item| {
                if (item.lookup("name")) |n| {
                    if (n.asString()) |s| {
                        if (std.mem.eql(u8, s, wanted)) break :blk item;
                    }
                }
            }
            return error.AtomicTestNotFound;
        },
    };
    if (test_node != .mapping) return error.NotAnArtAtomic;

    const test_name = (test_node.lookup("name") orelse return error.NotAnArtAtomic).asString()
        orelse return error.NotAnArtAtomic;
    const description = if (test_node.lookup("description")) |d|
        d.asString() orelse ""
    else
        "";

    // platforms
    var platforms: std.ArrayList([]const u8) = .empty;
    if (test_node.lookup("supported_platforms")) |p| {
        if (p == .sequence) {
            for (p.sequence) |plat| {
                if (plat.asString()) |s| try platforms.append(arena, try arena.dupe(u8, s));
            }
        }
    }

    // executor
    const executor = test_node.lookup("executor") orelse return error.UnsupportedExecutor;
    const exec_name = if (executor.lookup("name")) |n|
        n.asString() orelse ""
    else
        "";
    if (!std.mem.eql(u8, exec_name, "bash") and !std.mem.eql(u8, exec_name, "sh")) {
        return error.UnsupportedExecutor;
    }
    const raw_command = (executor.lookup("command") orelse return error.UnsupportedExecutor).asString()
        orelse return error.UnsupportedExecutor;

    // Substitute #{var} with the variable's `default` from input_arguments.
    const substituted = try substituteInputArgs(arena, raw_command, test_node);

    return Adapted{
        .id = try arena.dupe(u8, technique_id),
        .name = try arena.dupe(u8, test_name),
        .description = try arena.dupe(u8, description),
        .platforms = try platforms.toOwnedSlice(arena),
        .exec = substituted,
    };
}

/// Replace `#{var_name}` occurrences in `command` with the matching
/// `input_arguments[var_name].default` value. Unresolvable variables
/// are left literal — the shell will fail loudly, which is the right
/// behavior (silent substitution-with-empty-string would mask bugs).
fn substituteInputArgs(
    arena: std.mem.Allocator,
    command: []const u8,
    test_node: yaml.Node,
) ![]const u8 {
    const inputs = test_node.lookup("input_arguments") orelse {
        return arena.dupe(u8, command);
    };
    if (inputs != .mapping) return arena.dupe(u8, command);

    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < command.len) {
        if (i + 1 < command.len and command[i] == '#' and command[i + 1] == '{') {
            // Find matching close brace.
            const close = std.mem.indexOfScalarPos(u8, command, i + 2, '}') orelse {
                try out.append(arena, command[i]);
                i += 1;
                continue;
            };
            const var_name = command[i + 2 .. close];
            if (inputs.lookup(var_name)) |arg| {
                if (arg == .mapping) {
                    if (arg.lookup("default")) |def| {
                        if (def.asString()) |s| {
                            try out.appendSlice(arena, s);
                            i = close + 1;
                            continue;
                        }
                    }
                }
            }
            // Unresolved — keep literal.
            try out.appendSlice(arena, command[i .. close + 1]);
            i = close + 1;
        } else {
            try out.append(arena, command[i]);
            i += 1;
        }
    }
    return out.toOwnedSlice(arena);
}

// ─── Tests ──────────────────────────────────────────────────────────────────

test "adapt: minimal ART atomic" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const src =
        \\attack_technique: T1082
        \\display_name: System Information Discovery
        \\atomic_tests:
        \\- name: T1082 — uname
        \\  description: |
        \\    Read uname.
        \\  supported_platforms:
        \\  - linux
        \\  executor:
        \\    command: |
        \\      uname -a
        \\    name: bash
    ;
    const root = try yaml.parse(a, src);
    const result = try adapt(a, root, .first);
    try std.testing.expectEqualStrings("T1082", result.id);
    try std.testing.expectEqualStrings("T1082 — uname", result.name);
    try std.testing.expectEqualStrings("uname -a", result.exec);
    try std.testing.expect(result.platforms.len == 1);
    try std.testing.expectEqualStrings("linux", result.platforms[0]);
}

test "adapt: input_arguments substitution" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const src =
        \\attack_technique: T1082
        \\atomic_tests:
        \\- name: with-vars
        \\  input_arguments:
        \\    output_file:
        \\      description: where to write
        \\      type: Path
        \\      default: /tmp/out.txt
        \\  executor:
        \\    command: |
        \\      uname -a > #{output_file}
        \\    name: bash
    ;
    const root = try yaml.parse(a, src);
    const result = try adapt(a, root, .first);
    try std.testing.expectEqualStrings("uname -a > /tmp/out.txt", result.exec);
}

test "adapt: unsupported executor rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const src =
        \\attack_technique: T1059
        \\atomic_tests:
        \\- name: ps-only
        \\  executor:
        \\    command: |
        \\      Get-Process
        \\    name: powershell
    ;
    const root = try yaml.parse(a, src);
    try std.testing.expectError(error.UnsupportedExecutor, adapt(a, root, .first));
}

test "adapt: select by name" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const src =
        \\attack_technique: T1082
        \\atomic_tests:
        \\- name: first-test
        \\  executor:
        \\    command: |
        \\      echo first
        \\    name: bash
        \\- name: second-test
        \\  executor:
        \\    command: |
        \\      echo second
        \\    name: bash
    ;
    const root = try yaml.parse(a, src);
    const result = try adapt(a, root, .{ .name = "second-test" });
    try std.testing.expectEqualStrings("echo second", result.exec);
}

test "adapt: select by index" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const src =
        \\attack_technique: T1082
        \\atomic_tests:
        \\- name: zero
        \\  executor:
        \\    command: |
        \\      echo 0
        \\    name: bash
        \\- name: one
        \\  executor:
        \\    command: |
        \\      echo 1
        \\    name: bash
    ;
    const root = try yaml.parse(a, src);
    const result = try adapt(a, root, .{ .index = 1 });
    try std.testing.expectEqualStrings("echo 1", result.exec);
}
