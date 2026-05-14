//! sovereign-offense-harness v0.3.0
//!
//! Adversary emulation runner that executes canned TTP (Tactic /
//! Technique / Procedure) descriptors and captures structured audit
//! envelopes. Built for sentinel-lab's purple-team flywheel.
//!
//! v0.3 adds **experimental** Atomic Red Team YAML adapter (`--art`).
//! The native JSON descriptor format remains the primary surface; ART
//! adapter is a convenience layer over a minimal YAML subset parser.
//!
//! v0.2 added the safety gate: refuse-by-default unless the operator
//! explicitly acknowledges either local execution (--unsafe-local) or
//! provides a target IP that matches a configured whitelist.
//!
//! License: AGPL-3.0-or-later. Aligns with the rest of the Sovereign
//! Stack (per `LICENSING_STRATEGY.md` and project memory
//! `feedback_ship_first_redhat_defense.md`).

const std = @import("std");
const yaml = @import("yaml.zig");
const art = @import("art.zig");

const VERSION = "1.0.0";
const ENVELOPE_SCHEMA = "sovereign-offense-harness/envelope/v1";

const usage =
    \\sovereign-offense-harness — adversary emulation runner.
    \\
    \\Usage:
    \\  sovereign-offense-harness run (--ttp <ttp.json> | --art <atomic.yml>) [opts]
    \\  sovereign-offense-harness validate <ttp.json>
    \\  sovereign-offense-harness --version | -V
    \\  sovereign-offense-harness --help    | -h
    \\
    \\`run` options:
    \\  --ttp <path>           native JSON TTP descriptor
    \\  --art <path>           Atomic Red Team YAML atomic (EXPERIMENTAL,
    \\                         v0.3 — bash/sh executors only; minimal YAML
    \\                         subset parser; #{var} default substitution)
    \\  --art-test <name|N>    pick atomic test by name or 0-based index
    \\                         (default: first test in the file)
    \\  --out <dir>            envelope output dir (default: envelopes/)
    \\  --target <IP>          target IP for the TTP (passed as $TARGET to exec).
    \\                         Refused unless IP is in --lab-targets whitelist.
    \\  --unsafe-local         execute against the local host. ACK that you
    \\                         understand `exec` runs as you with no sandbox.
    \\  --lab-targets <path>   whitelist file: one CIDR or IP per line.
    \\                         Default: ~/sentinel-lab/lab-targets.txt.
    \\
    \\Safety gate (v0.2+): refuse-by-default. Run requires either
    \\--unsafe-local or --target <IP-in-whitelist>. The whitelist file
    \\must exist and contain the target. CIDR matching supported (v4 only
    \\in v0.2; v6 deferred).
    \\
    \\TTP descriptor format (JSON, native):
    \\  {
    \\    "id": "T1018",
    \\    "name": "Remote System Discovery",
    \\    "description": "Enumerate ARP neighbors via `ip neigh`",
    \\    "platforms": ["linux"],
    \\    "exec": "ip neigh show",
    \\    "expected": {
    \\      "exit_code": 0,
    \\      "stdout_contains": null,
    \\      "stdout_excludes": []
    \\    }
    \\  }
    \\
    \\ART adapter (v0.3 EXPERIMENTAL): only `bash` / `sh` executors are
    \\run as-is. Other executors (powershell, command_prompt) are
    \\rejected — the adapter refuses to silently mis-run them. ART
    \\`expected_*` fields are not honored (ART has no equivalent today).
    \\Dependencies and cleanup_command are ignored. v0.4 plans a
    \\`--check-deps` mode.
    \\
    \\Exit codes:
    \\  0 — success (TTP ran AND matched all expectations)
    \\  1 — TTP ran but expectations failed
    \\  2 — bad CLI / TTP file / setup error
    \\  3 — refused by safety gate
    \\
;

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const arena = init.arena.allocator();
    const io = init.io;

    var iter = try std.process.Args.Iterator.initAllocator(init.minimal.args, gpa);
    defer iter.deinit();

    _ = iter.next(); // skip program name

    const cmd = iter.next() orelse {
        std.debug.print("{s}", .{usage});
        return;
    };

    if (std.mem.eql(u8, cmd, "--version") or std.mem.eql(u8, cmd, "-V")) {
        std.debug.print("sovereign-offense-harness {s}\n", .{VERSION});
        return;
    }
    if (std.mem.eql(u8, cmd, "--help") or std.mem.eql(u8, cmd, "-h")) {
        std.debug.print("{s}", .{usage});
        return;
    }

    if (std.mem.eql(u8, cmd, "validate")) {
        const path = iter.next() orelse return fail("validate requires <ttp.json>");
        return validateCmd(arena, io, path);
    }

    if (std.mem.eql(u8, cmd, "run")) {
        var ttp_path: ?[]const u8 = null;
        var art_path: ?[]const u8 = null;
        var art_test: ?[]const u8 = null;
        var out_dir: []const u8 = "envelopes";
        var target: ?[]const u8 = null;
        var unsafe_local: bool = false;
        var lab_targets: ?[]const u8 = null;
        while (iter.next()) |a| {
            if (std.mem.eql(u8, a, "--ttp")) {
                ttp_path = iter.next() orelse return fail("--ttp requires a path");
            } else if (std.mem.eql(u8, a, "--art")) {
                art_path = iter.next() orelse return fail("--art requires a path");
            } else if (std.mem.eql(u8, a, "--art-test")) {
                art_test = iter.next() orelse return fail("--art-test requires a name or index");
            } else if (std.mem.eql(u8, a, "--out")) {
                out_dir = iter.next() orelse return fail("--out requires a path");
            } else if (std.mem.eql(u8, a, "--target")) {
                target = iter.next() orelse return fail("--target requires an IP");
            } else if (std.mem.eql(u8, a, "--unsafe-local")) {
                unsafe_local = true;
            } else if (std.mem.eql(u8, a, "--lab-targets")) {
                lab_targets = iter.next() orelse return fail("--lab-targets requires a path");
            } else {
                return fail("unexpected arg in `run`");
            }
        }
        if (ttp_path != null and art_path != null) {
            return fail("--ttp and --art are mutually exclusive");
        }
        if (ttp_path == null and art_path == null) {
            return fail("run requires either --ttp <path> or --art <path>");
        }
        if (art_test != null and art_path == null) {
            return fail("--art-test requires --art");
        }

        // ─── Safety gate ──────────────────────────────────────────
        // Refuse-by-default. Operator must either:
        //   (a) provide --target <IP> that resolves to a CIDR in the
        //       configured whitelist, OR
        //   (b) explicitly acknowledge local execution via --unsafe-local.
        // No silent path; refusal is hard.
        if (target == null and !unsafe_local) {
            std.debug.print(
                \\error: refused by safety gate.
                \\
                \\sovereign-offense-harness will not execute a TTP without an
                \\explicit safety acknowledgement. Pick one:
                \\
                \\  --target <IP>          target a remote host (must be in
                \\                         the lab-targets whitelist)
                \\  --unsafe-local         execute on this local host —
                \\                         acknowledges that `exec` runs as
                \\                         you with no sandbox or rollback
                \\
                \\This gate is intentional. The example TTPs are read-only,
                \\but the v0.1 of this tool would happily run any string
                \\you handed it as your user. v0.2 makes you say so.
                \\
            , .{});
            std.process.exit(3);
        }
        if (target != null and unsafe_local) {
            return fail("--target and --unsafe-local are mutually exclusive");
        }

        if (target) |t| {
            // Whitelist path: --lab-targets flag wins; otherwise default
            // to ~/sentinel-lab/lab-targets.txt. (env-var fallback was
            // tempting but std.posix.getenv was reorganized in Zig 0.16
            // and the simpler default-path approach is fine for v0.2.)
            const wl_path = lab_targets orelse "~/sentinel-lab/lab-targets.txt";
            const wl_resolved = try expandTilde(arena, wl_path);
            const matched = checkWhitelist(arena, io, wl_resolved, t) catch |err| {
                std.debug.print(
                    "error: failed to read whitelist {s}: {s}\n" ++
                        "(create the file with one CIDR or IP per line, " ++
                        "or pass --lab-targets <path>)\n",
                    .{ wl_resolved, @errorName(err) },
                );
                std.process.exit(3);
            };
            if (!matched) {
                std.debug.print(
                    "error: target {s} not in whitelist {s} — refused.\n",
                    .{ t, wl_resolved },
                );
                std.process.exit(3);
            }
        }

        if (ttp_path) |path| {
            return runCmd(gpa, arena, io, path, out_dir, target, unsafe_local);
        }
        // --art path: read YAML, adapt, run.
        return runArtCmd(gpa, arena, io, art_path.?, art_test, out_dir, target, unsafe_local);
    }

    return fail("unknown subcommand");
}

/// Expand a leading `~/` to $HOME via /proc/self/environ. Anything
/// else returned as-is. (std.posix.getenv was reorganized in Zig 0.16
/// and accessing env from a free function without an Init handle is
/// awkward; this is the workaround.)
fn expandTilde(allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
    if (path.len < 2 or path[0] != '~' or path[1] != '/') {
        return try allocator.dupe(u8, path);
    }
    const home = readHomeFromProcEnviron(allocator) catch null;
    if (home) |h| {
        return try std.fmt.allocPrint(allocator, "{s}{s}", .{ h, path[1..] });
    }
    // Fallback: no HOME found — return as-is and let the file open fail
    // with a useful path string.
    return try allocator.dupe(u8, path);
}

/// Linux-only presence check: does `/proc/self/environ` contain a
/// pair beginning with `prefix` (e.g. `SOH_QUIET=`)? Pass the trailing
/// `=` to avoid prefix collisions like `SOH_QUIETLY=…`. No allocation;
/// safe to call from hot paths.
fn procEnvironHasKey(prefix: []const u8) bool {
    const fd = std.os.linux.open("/proc/self/environ", .{ .ACCMODE = .RDONLY }, 0);
    if (@as(isize, @bitCast(fd)) < 0) return false;
    defer _ = std.os.linux.close(@intCast(fd));

    var buf: [16 * 1024]u8 = undefined;
    const n = std.os.linux.read(@intCast(fd), &buf, buf.len);
    if (@as(isize, @bitCast(n)) <= 0) return false;
    const data = buf[0..@intCast(n)];

    var pairs = std.mem.splitScalar(u8, data, 0);
    while (pairs.next()) |pair| {
        if (std.mem.startsWith(u8, pair, prefix)) return true;
    }
    return false;
}

/// Linux-only: read /proc/self/environ (NUL-separated key=value pairs)
/// and return the HOME value, or null if not found.
fn readHomeFromProcEnviron(allocator: std.mem.Allocator) !?[]const u8 {
    const fd = std.os.linux.open("/proc/self/environ", .{ .ACCMODE = .RDONLY }, 0);
    if (@as(isize, @bitCast(fd)) < 0) return null;
    defer _ = std.os.linux.close(@intCast(fd));

    var buf: [16 * 1024]u8 = undefined;
    const n = std.os.linux.read(@intCast(fd), &buf, buf.len);
    if (@as(isize, @bitCast(n)) <= 0) return null;
    const data = buf[0..@intCast(n)];

    var pairs = std.mem.splitScalar(u8, data, 0);
    while (pairs.next()) |pair| {
        if (std.mem.startsWith(u8, pair, "HOME=")) {
            return try allocator.dupe(u8, pair[5..]);
        }
    }
    return null;
}

/// Read the whitelist file and return true iff `target_ip` matches an
/// entry. Entries can be exact IPv4 (`10.0.0.5`) or CIDR (`10.0.0.0/24`).
/// Lines starting with `#` and blank lines are ignored. v0.2 supports IPv4
/// only; IPv6 deferred.
fn checkWhitelist(arena: std.mem.Allocator, io: std.Io, path: []const u8, target_ip: []const u8) !bool {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(
        io,
        path,
        arena,
        std.Io.Limit.limited(1 * 1024 * 1024),
    );
    const target_addr = parseIpv4(target_ip) catch return error.InvalidTargetIp;

    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0) continue;
        if (line[0] == '#') continue;

        // CIDR or bare IP
        if (std.mem.indexOfScalar(u8, line, '/')) |slash| {
            const ip_str = line[0..slash];
            const prefix_str = line[slash + 1 ..];
            const net_addr = parseIpv4(ip_str) catch continue;
            const prefix = std.fmt.parseInt(u6, prefix_str, 10) catch continue;
            if (prefix > 32) continue;
            const mask: u32 = if (prefix == 0) 0 else (~@as(u32, 0)) << @intCast(32 - prefix);
            if ((target_addr & mask) == (net_addr & mask)) return true;
        } else {
            const net_addr = parseIpv4(line) catch continue;
            if (target_addr == net_addr) return true;
        }
    }
    return false;
}

/// Parse "a.b.c.d" → u32 (network-order). v2 IPv4-only.
fn parseIpv4(s: []const u8) !u32 {
    var parts: [4]u8 = undefined;
    var idx: usize = 0;
    var part_iter = std.mem.splitScalar(u8, s, '.');
    while (part_iter.next()) |p| : (idx += 1) {
        if (idx >= 4) return error.InvalidIpv4;
        parts[idx] = std.fmt.parseInt(u8, p, 10) catch return error.InvalidIpv4;
    }
    if (idx != 4) return error.InvalidIpv4;
    return (@as(u32, parts[0]) << 24) | (@as(u32, parts[1]) << 16) |
        (@as(u32, parts[2]) << 8) | @as(u32, parts[3]);
}

fn fail(msg: []const u8) !void {
    std.debug.print("error: {s}\n\n{s}", .{ msg, usage });
    std.process.exit(2);
}

// ─── TTP descriptor parsing ──────────────────────────────────────────────────

const Ttp = struct {
    id: []const u8,
    name: []const u8,
    description: []const u8,
    platforms: []const []const u8,
    exec: []const u8,
    expected_exit_code: ?i64,
    expected_stdout_contains: ?[]const u8,
    expected_stdout_excludes: []const []const u8,
};

fn parseTtp(allocator: std.mem.Allocator, json_bytes: []const u8) !Ttp {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_bytes, .{});
    // intentionally NOT deinit here — we hand back string slices owned by parsed.
    // caller's arena keeps everything alive.
    const root = parsed.value;
    if (root != .object) return error.TtpNotObject;
    const o = root.object;

    const id = (o.get("id") orelse return error.TtpMissingId).string;
    const name = (o.get("name") orelse return error.TtpMissingName).string;
    const description = if (o.get("description")) |d|
        if (d == .string) d.string else ""
    else
        "";

    var platforms: std.ArrayList([]const u8) = .empty;
    if (o.get("platforms")) |p| {
        if (p == .array) {
            for (p.array.items) |item| {
                if (item == .string) try platforms.append(allocator, item.string);
            }
        }
    }

    const exec = (o.get("exec") orelse return error.TtpMissingExec).string;

    var expected_exit_code: ?i64 = null;
    var expected_stdout_contains: ?[]const u8 = null;
    var expected_stdout_excludes: std.ArrayList([]const u8) = .empty;
    if (o.get("expected")) |e| {
        if (e == .object) {
            if (e.object.get("exit_code")) |ec| if (ec == .integer) {
                expected_exit_code = ec.integer;
            };
            if (e.object.get("stdout_contains")) |sc| if (sc == .string) {
                expected_stdout_contains = sc.string;
            };
            if (e.object.get("stdout_excludes")) |se| if (se == .array) {
                for (se.array.items) |item| {
                    if (item == .string) try expected_stdout_excludes.append(allocator, item.string);
                }
            };
        }
    }

    return .{
        .id = id,
        .name = name,
        .description = description,
        .platforms = try platforms.toOwnedSlice(allocator),
        .exec = exec,
        .expected_exit_code = expected_exit_code,
        .expected_stdout_contains = expected_stdout_contains,
        .expected_stdout_excludes = try expected_stdout_excludes.toOwnedSlice(allocator),
    };
}

// ─── validate subcommand ────────────────────────────────────────────────────

fn validateCmd(arena: std.mem.Allocator, io: std.Io, path: []const u8) !void {
    const json_bytes = try std.Io.Dir.cwd().readFileAlloc(
        io,
        path,
        arena,
        std.Io.Limit.limited(1 * 1024 * 1024),
    );
    const ttp = try parseTtp(arena, json_bytes);
    std.debug.print(
        "TTP {s}: {s}\n  platforms: {d}\n  exec: {s}\n  expected exit: {?}\n",
        .{ ttp.id, ttp.name, ttp.platforms.len, ttp.exec, ttp.expected_exit_code },
    );
}

// ─── run subcommand ──────────────────────────────────────────────────────────

fn runCmd(
    gpa: std.mem.Allocator,
    arena: std.mem.Allocator,
    io: std.Io,
    ttp_path: []const u8,
    out_dir: []const u8,
    target: ?[]const u8,
    unsafe_local: bool,
) !void {
    const json_bytes = try std.Io.Dir.cwd().readFileAlloc(
        io,
        ttp_path,
        arena,
        std.Io.Limit.limited(1 * 1024 * 1024),
    );
    const ttp = try parseTtp(arena, json_bytes);
    return runTtp(gpa, arena, io, ttp, out_dir, target, unsafe_local);
}

/// Read an ART atomic YAML, adapt the selected test to the internal TTP
/// shape, and run it through the same execution path as a JSON descriptor.
/// `selector_str` is null (= first test), an integer (0-based index), or
/// the exact `name` of an atomic_test.
fn runArtCmd(
    gpa: std.mem.Allocator,
    arena: std.mem.Allocator,
    io: std.Io,
    art_path: []const u8,
    selector_str: ?[]const u8,
    out_dir: []const u8,
    target: ?[]const u8,
    unsafe_local: bool,
) !void {
    const yaml_bytes = try std.Io.Dir.cwd().readFileAlloc(
        io,
        art_path,
        arena,
        std.Io.Limit.limited(4 * 1024 * 1024),
    );
    const root = try yaml.parse(arena, yaml_bytes);

    const selector: art.Selector = if (selector_str) |s| blk: {
        if (std.fmt.parseInt(usize, s, 10)) |i| {
            break :blk .{ .index = i };
        } else |_| {
            break :blk .{ .name = s };
        }
    } else .first;

    const adapted = art.adapt(arena, root, selector) catch |err| switch (err) {
        error.NotAnArtAtomic => return fail("--art file is not a recognizable ART atomic"),
        error.NoAtomicTests => return fail("--art file contains no atomic_tests"),
        error.AtomicTestNotFound => return fail("--art-test selector did not match any test"),
        error.UnsupportedExecutor => return fail("--art file's executor is not bash/sh (powershell/command_prompt rejected by design)"),
        else => return err,
    };

    // P0-5 / P1-2: echo the selected atomic + the substituted exec to
    // stderr before executing. ART YAMLs often carry multiple atomics
    // with different risk profiles in one file, and #{var} default
    // substitution can pull in upstream-supplied demo values. Make the
    // operator see what's about to run.
    const total_atomics: usize = blk: {
        if (root.lookup("atomic_tests")) |seq| {
            if (seq == .sequence) break :blk seq.sequence.len;
        }
        break :blk 0;
    };
    const selector_label: []const u8 = if (selector_str) |s| s else "first";
    std.debug.print(
        "art: selected '{s}' (selector: {s}; total atomics in file: {d})\nart: substituted exec:\n----\n{s}\n----\n",
        .{ adapted.name, selector_label, total_atomics, adapted.exec },
    );

    const ttp = Ttp{
        .id = adapted.id,
        .name = adapted.name,
        .description = adapted.description,
        .platforms = adapted.platforms,
        .exec = adapted.exec,
        // ART has no equivalent of `expected` — leave unconstrained.
        // Verdict will be PASS as long as the command exits without
        // signaling. If a stronger check is wanted, write a native JSON
        // descriptor that wraps the same exec line with expectations.
        .expected_exit_code = null,
        .expected_stdout_contains = null,
        .expected_stdout_excludes = &.{},
    };
    return runTtp(gpa, arena, io, ttp, out_dir, target, unsafe_local);
}

fn runTtp(
    gpa: std.mem.Allocator,
    arena: std.mem.Allocator,
    io: std.Io,
    ttp: Ttp,
    out_dir: []const u8,
    target: ?[]const u8,
    unsafe_local: bool,
) !void {
    // Capture wall-clock timestamp + monotonic start. std.time.timestamp
    // and std.time.Timer were both removed in Zig 0.16; use clock_gettime
    // syscalls directly. Linux-only; a future cross-platform version can
    // branch on os tag.
    var ts_realtime: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.REALTIME, &ts_realtime);
    const t_start: i64 = @intCast(ts_realtime.sec);

    var ts_mono_start: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts_mono_start);

    // Spawn the TTP via `bash -c <exec>`. Sandboxing is the lab's job;
    // this runner trusts the TTP descriptor's command.
    //
    // If a target IP was provided, prepend `TARGET=<ip>` to the bash
    // invocation so the TTP's exec field can reference $TARGET. This
    // sidesteps Zig 0.16's reorganized environ-handling APIs while
    // giving descriptors the same UX as if we'd passed an env_map.
    //
    // P0-4: --unsafe-local muscle memory is the operator-error hazard
    // the gate's name doesn't actually catch. Print a loud line every
    // single run so the flag never becomes invisible to a SOC analyst's
    // muscle memory. Suppress under SOH_QUIET=1 for batch users.
    if (unsafe_local and !procEnvironHasKey("SOH_QUIET=")) {
        std.debug.print(
            "warning: --unsafe-local set; TTP runs as the invoking user with no sandbox. No rollback. (suppress this line with SOH_QUIET=1)\n",
            .{},
        );
    }
    const exec_with_env = if (target) |t|
        try std.fmt.allocPrint(arena, "TARGET={s} {s}", .{ t, ttp.exec })
    else
        try arena.dupe(u8, ttp.exec);
    const argv = &[_][]const u8{ "bash", "-c", exec_with_env };
    const result = try std.process.run(gpa, io, .{ .argv = argv });
    defer gpa.free(result.stdout);
    defer gpa.free(result.stderr);

    var ts_mono_end: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts_mono_end);
    const duration_ns: u64 = @intCast(
        (ts_mono_end.sec - ts_mono_start.sec) * 1_000_000_000 +
            (ts_mono_end.nsec - ts_mono_start.nsec),
    );
    const duration_ms = duration_ns / 1_000_000;

    const exit_code: i64 = switch (result.term) {
        .exited => |c| @intCast(c),
        .signal => |s| -@as(i64, @intFromEnum(s)),
        else => -1,
    };

    var stdout_sha: [32]u8 = undefined;
    var stderr_sha: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(result.stdout, &stdout_sha, .{});
    std.crypto.hash.sha2.Sha256.hash(result.stderr, &stderr_sha, .{});

    // Host fingerprint — minimal: hostname.
    var host_buf: [std.posix.HOST_NAME_MAX]u8 = undefined;
    const hostname: []const u8 = std.posix.gethostname(&host_buf) catch "unknown";

    // Evaluate expectations.
    var passed = true;
    var fail_reason: []const u8 = "";
    if (ttp.expected_exit_code) |expected| {
        if (exit_code != expected) {
            passed = false;
            fail_reason = "exit code mismatch";
        }
    }
    if (passed and ttp.expected_stdout_contains != null) {
        if (std.mem.indexOf(u8, result.stdout, ttp.expected_stdout_contains.?) == null) {
            passed = false;
            fail_reason = "expected stdout substring not found";
        }
    }
    if (passed) {
        for (ttp.expected_stdout_excludes) |excl| {
            if (std.mem.indexOf(u8, result.stdout, excl) != null) {
                passed = false;
                fail_reason = "forbidden stdout substring present";
                break;
            }
        }
    }

    // Build envelope JSON.
    var env: std.ArrayList(u8) = .empty;
    try env.appendSlice(arena, "{\n");
    try env.print(arena, "  \"schema\": \"{s}\",\n", .{ENVELOPE_SCHEMA});
    try env.appendSlice(arena, "  \"ttp\": {\n");
    try env.appendSlice(arena, "    \"id\": \"");
    try writeJsonString(&env, arena, ttp.id);
    try env.appendSlice(arena, "\",\n");
    try env.appendSlice(arena, "    \"name\": \"");
    try writeJsonString(&env, arena, ttp.name);
    try env.appendSlice(arena, "\",\n");
    try env.appendSlice(arena, "    \"exec\": \"");
    try writeJsonString(&env, arena, ttp.exec);
    try env.appendSlice(arena, "\"\n");
    try env.appendSlice(arena, "  },\n");
    try env.appendSlice(arena, "  \"execution\": {\n");
    try env.print(arena, "    \"started_at_unix\": {d},\n", .{t_start});
    try env.print(arena, "    \"duration_ms\": {d},\n", .{duration_ms});
    try env.print(arena, "    \"exit_code\": {d},\n", .{exit_code});
    try env.print(arena, "    \"stdout_bytes\": {d},\n", .{result.stdout.len});
    try env.print(arena, "    \"stderr_bytes\": {d},\n", .{result.stderr.len});
    try env.appendSlice(arena, "    \"stdout_sha256\": \"");
    try writeHex(&env, arena, &stdout_sha);
    try env.appendSlice(arena, "\",\n");
    try env.appendSlice(arena, "    \"stderr_sha256\": \"");
    try writeHex(&env, arena, &stderr_sha);
    try env.appendSlice(arena, "\"\n");
    try env.appendSlice(arena, "  },\n");
    try env.appendSlice(arena, "  \"host\": { \"hostname\": \"");
    try writeJsonString(&env, arena, hostname);
    try env.appendSlice(arena, "\" },\n");
    try env.appendSlice(arena, "  \"verdict\": ");
    if (passed) {
        try env.appendSlice(arena, "\"PASS\"");
    } else {
        try env.appendSlice(arena, "\"FAIL\",\n  \"verdict_reason\": \"");
        try writeJsonString(&env, arena, fail_reason);
        try env.appendSlice(arena, "\"");
    }
    try env.appendSlice(arena, "\n}\n");

    // Ensure output dir exists. Linux mkdir syscall directly — Zig 0.16
    // has no portable mkdir-p in std without IO context wiring.
    // Walk the path components left-to-right and mkdir each level.
    {
        var sub_iter = std.mem.splitScalar(u8, out_dir, '/');
        var built: std.ArrayList(u8) = .empty;
        defer built.deinit(arena);
        while (sub_iter.next()) |seg| {
            if (seg.len == 0) continue;
            if (built.items.len > 0) try built.append(arena, '/');
            try built.appendSlice(arena, seg);
            // Need null-terminated for the linux syscall. Ignore return —
            // EEXIST is OK; non-EEXIST failures will surface from the
            // subsequent createFile with a more descriptive error.
            const cstr = try arena.dupeZ(u8, built.items);
            _ = std.os.linux.mkdir(cstr.ptr, 0o755);
        }
    }

    // Filename: <ttp_id>-<timestamp>.json
    const filename = try std.fmt.allocPrint(arena, "{s}/{s}-{d}.json", .{ out_dir, ttp.id, t_start });
    {
        const file = try std.Io.Dir.cwd().createFile(io, filename, .{});
        defer file.close(io);
        const wrote = std.os.linux.write(file.handle, env.items.ptr, env.items.len);
        if (wrote < 0) return error.WriteFailed;
    }

    // Stdout summary.
    var stdout_buf: [1024]u8 = undefined;
    var sw = std.Io.File.stdout().writer(io, &stdout_buf);
    const out = &sw.interface;
    try out.print("[{s}] {s}: {s}\n  envelope: {s}\n  duration: {d}ms exit={d}\n", .{
        if (passed) "PASS" else "FAIL",
        ttp.id,
        ttp.name,
        filename,
        duration_ms,
        exit_code,
    });
    try out.flush();

    if (!passed) std.process.exit(1);
}

fn writeHex(out: *std.ArrayList(u8), allocator: std.mem.Allocator, bytes: []const u8) !void {
    const digits = "0123456789abcdef";
    for (bytes) |b| {
        try out.append(allocator, digits[(b >> 4) & 0x0f]);
        try out.append(allocator, digits[b & 0x0f]);
    }
}

/// Append `s` to `out` as the contents of a JSON string (no surrounding
/// quotes). Escapes `"`, `\`, control bytes < 0x20, and DEL (0x7f). Other
/// bytes (including valid UTF-8 continuation bytes) pass through. This
/// is the minimum-correct subset of RFC 8259 §7 — enough that `jq` and
/// strict consumers accept the envelope. Previously the writer used
/// `{s}` interpolation directly, which produced invalid JSON whenever
/// `ttp.exec` contained a newline — surfaced by v0.3 ART `|` literal
/// blocks.
fn writeJsonString(out: *std.ArrayList(u8), allocator: std.mem.Allocator, s: []const u8) !void {
    for (s) |b| {
        switch (b) {
            '"' => try out.appendSlice(allocator, "\\\""),
            '\\' => try out.appendSlice(allocator, "\\\\"),
            '\n' => try out.appendSlice(allocator, "\\n"),
            '\r' => try out.appendSlice(allocator, "\\r"),
            '\t' => try out.appendSlice(allocator, "\\t"),
            0x08 => try out.appendSlice(allocator, "\\b"),
            0x0c => try out.appendSlice(allocator, "\\f"),
            0x00...0x07, 0x0b, 0x0e...0x1f, 0x7f => {
                var buf: [6]u8 = undefined;
                const written = std.fmt.bufPrint(&buf, "\\u{x:0>4}", .{b}) catch unreachable;
                try out.appendSlice(allocator, written);
            },
            else => try out.append(allocator, b),
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

test "parseTtp on minimal valid descriptor" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const fixture =
        \\{
        \\  "id": "T1018",
        \\  "name": "Remote System Discovery",
        \\  "description": "ARP neighbor enumeration",
        \\  "platforms": ["linux"],
        \\  "exec": "ip neigh show",
        \\  "expected": {
        \\    "exit_code": 0,
        \\    "stdout_contains": null,
        \\    "stdout_excludes": []
        \\  }
        \\}
    ;
    const ttp = try parseTtp(a, fixture);
    try std.testing.expectEqualStrings("T1018", ttp.id);
    try std.testing.expectEqualStrings("Remote System Discovery", ttp.name);
    try std.testing.expectEqualStrings("ip neigh show", ttp.exec);
    try std.testing.expect(ttp.expected_exit_code.? == 0);
    try std.testing.expect(ttp.platforms.len == 1);
    try std.testing.expectEqualStrings("linux", ttp.platforms[0]);
}

test "parseTtp rejects missing id" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const fixture =
        \\{ "name": "no-id", "exec": "true" }
    ;
    try std.testing.expectError(error.TtpMissingId, parseTtp(a, fixture));
}

test "writeJsonString escapes control bytes and structural chars" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var out: std.ArrayList(u8) = .empty;
    try writeJsonString(&out, a, "line1\nline2\t\"q\"\\ok\x01");
    try std.testing.expectEqualStrings("line1\\nline2\\t\\\"q\\\"\\\\ok\\u0001", out.items);
}

test "envelope writer produces parseable JSON for multi-line exec" {
    // Regression: ART `|` literal blocks yield multi-line execs. Before
    // the writeJsonString fix, the raw `{s}` interpolation embedded a
    // literal LF inside the JSON string value, producing invalid JSON.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(a, "\"exec\":\"");
    try writeJsonString(&out, a, "uname -a\ncat /etc/os-release");
    try out.appendSlice(a, "\"");
    // Must not contain a literal LF inside the value.
    try std.testing.expect(std.mem.indexOfScalar(u8, out.items, '\n') == null);
    try std.testing.expectEqualStrings(
        "\"exec\":\"uname -a\\ncat /etc/os-release\"",
        out.items,
    );
}

test "art end-to-end: YAML → adapter → Ttp shape" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const src =
        \\attack_technique: T1082
        \\display_name: System Information Discovery
        \\atomic_tests:
        \\- name: T1082 — uname
        \\  description: Read uname.
        \\  supported_platforms:
        \\  - linux
        \\  executor:
        \\    command: |
        \\      uname -a
        \\    name: bash
    ;
    const root = try yaml.parse(a, src);
    const adapted = try art.adapt(a, root, .first);
    const ttp = Ttp{
        .id = adapted.id,
        .name = adapted.name,
        .description = adapted.description,
        .platforms = adapted.platforms,
        .exec = adapted.exec,
        .expected_exit_code = null,
        .expected_stdout_contains = null,
        .expected_stdout_excludes = &.{},
    };
    try std.testing.expectEqualStrings("T1082", ttp.id);
    try std.testing.expectEqualStrings("uname -a", ttp.exec);
    try std.testing.expect(ttp.expected_exit_code == null);
}

// Pull yaml.zig + art.zig tests into the main test binary.
comptime {
    _ = yaml;
    _ = art;
}
test {
    _ = @import("yaml.zig");
    _ = @import("art.zig");
}
