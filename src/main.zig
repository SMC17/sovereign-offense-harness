//! sovereign-offense-harness v0.1.0
//!
//! Adversary emulation runner that executes canned TTP (Tactic /
//! Technique / Procedure) descriptors and captures structured audit
//! envelopes. Built for sentinel-lab's purple-team flywheel.
//!
//! v0.1 scope (per ~/COMPETITIVE_LANDSCAPE.md S1 acceptance gate):
//!   sketch → compiled. Passes when:
//!   - `zig build` produces a working binary.
//!   - `sentinel-offense run --ttp ttps/examples/t1018.json` executes
//!     and writes a JSON envelope to envelopes/.
//!   - The envelope contains: ttp metadata, exec command, exit code,
//!     stdout/stderr (full text + sha256), host fingerprint, timestamps.
//!
//! v0.2 scope (deferred):
//!   - Local-LLM-driven TTP selection ("which TTPs should I run against
//!     this target?") via local Ollama / vLLM endpoint.
//!   - Sigma rule + Velociraptor artifact emission from observed gaps.
//!   - sentinel-lab integration: read lab inventory, target whitelist,
//!     refuse to execute outside the lab IP range.
//!
//! License: AGPL-3.0-or-later. Aligns with the rest of the Sovereign
//! Stack (per `LICENSING_STRATEGY.md` and project memory
//! `feedback_ship_first_redhat_defense.md`).

const std = @import("std");

const VERSION = "0.1.0";
const ENVELOPE_SCHEMA = "sovereign-offense-harness/envelope/v1";

const usage =
    \\sovereign-offense-harness — adversary emulation runner.
    \\
    \\Usage:
    \\  sovereign-offense-harness run --ttp <ttp.json> [--out <dir>]
    \\  sovereign-offense-harness validate <ttp.json>
    \\  sovereign-offense-harness --version | -V
    \\  sovereign-offense-harness --help    | -h
    \\
    \\TTP descriptor format (JSON):
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
    \\Exit codes:
    \\  0 — success (TTP ran AND matched all expectations)
    \\  1 — TTP ran but expectations failed
    \\  2 — bad CLI / TTP file / setup error
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
        var out_dir: []const u8 = "envelopes";
        while (iter.next()) |a| {
            if (std.mem.eql(u8, a, "--ttp")) {
                ttp_path = iter.next() orelse return fail("--ttp requires a path");
            } else if (std.mem.eql(u8, a, "--out")) {
                out_dir = iter.next() orelse return fail("--out requires a path");
            } else {
                return fail("unexpected arg in `run`");
            }
        }
        const path = ttp_path orelse return fail("run requires --ttp <path>");
        return runCmd(gpa, arena, io, path, out_dir);
    }

    return fail("unknown subcommand");
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

fn runCmd(gpa: std.mem.Allocator, arena: std.mem.Allocator, io: std.Io, ttp_path: []const u8, out_dir: []const u8) !void {
    const json_bytes = try std.Io.Dir.cwd().readFileAlloc(
        io,
        ttp_path,
        arena,
        std.Io.Limit.limited(1 * 1024 * 1024),
    );
    const ttp = try parseTtp(arena, json_bytes);

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
    const argv = &[_][]const u8{ "bash", "-c", ttp.exec };
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
    try env.print(arena, "    \"id\": \"{s}\",\n", .{ttp.id});
    try env.print(arena, "    \"name\": \"{s}\",\n", .{ttp.name});
    try env.print(arena, "    \"exec\": \"{s}\"\n", .{ttp.exec});
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
    try env.print(arena, "  \"host\": {{ \"hostname\": \"{s}\" }},\n", .{hostname});
    try env.appendSlice(arena, "  \"verdict\": ");
    if (passed) {
        try env.appendSlice(arena, "\"PASS\"");
    } else {
        try env.print(arena, "\"FAIL\",\n  \"verdict_reason\": \"{s}\"", .{fail_reason});
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
