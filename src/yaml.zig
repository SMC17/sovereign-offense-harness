//! Minimal YAML subset parser — just enough to read Atomic Red Team
//! atomic descriptors. NOT a full YAML 1.2 implementation; deliberately
//! narrow.
//!
//! Supported:
//!   - Block-style mappings (`key: value`, `key:` followed by indented body)
//!   - Block-style sequences (`- item`, `- key: value` for compact mappings)
//!   - Plain scalars (strings, numbers, booleans treated as strings)
//!   - Single-quoted and double-quoted strings (no escape handling beyond
//!     stripping the surrounding quotes — ART atomics don't use escapes
//!     in scalar fields we care about)
//!   - Block scalar literal `|` (preserves newlines)
//!   - Block scalar folded `>` (treated as literal here — ART rarely uses
//!     `>` in practice and conflating the two is honest within this scope)
//!   - `#` comments to end of line
//!   - Empty lines
//!   - Sequence-at-same-indent-as-parent-mapping-key (the "compact" YAML idiom)
//!
//! NOT supported:
//!   - Anchors / aliases (`&foo` / `*foo`)
//!   - Tags (`!!str`, `!Tag`)
//!   - Flow style (`{a: 1, b: 2}` / `[1, 2, 3]`)
//!   - Multi-document streams (`---` / `...`)
//!   - Complex keys (`? key`)
//!   - Tab characters in indentation (spaces only)
//!   - Quoted-string escapes beyond "strip surrounding quote pair"
//!
//! These restrictions are intentional. ART atomics use a small slice of
//! YAML; supporting more would expand the parser surface (and the
//! supply-chain audit surface) for no v0.3 gain.

const std = @import("std");

pub const Node = union(enum) {
    scalar: []const u8,
    sequence: []Node,
    mapping: []Kv,

    pub fn lookup(self: Node, key: []const u8) ?Node {
        if (self != .mapping) return null;
        for (self.mapping) |kv| {
            if (std.mem.eql(u8, kv.key, key)) return kv.value;
        }
        return null;
    }

    pub fn asString(self: Node) ?[]const u8 {
        return switch (self) {
            .scalar => |s| s,
            else => null,
        };
    }
};

pub const Kv = struct {
    key: []const u8,
    value: Node,
};

pub const ParseError = error{
    InvalidYaml,
    UnexpectedEof,
    OutOfMemory,
};

pub fn parse(arena: std.mem.Allocator, source: []const u8) ParseError!Node {
    var lines: std.ArrayList([]const u8) = .empty;
    var line_iter = std.mem.splitScalar(u8, source, '\n');
    while (line_iter.next()) |raw| {
        // Strip trailing carriage return; keep leading whitespace (indent matters).
        const stripped = if (raw.len > 0 and raw[raw.len - 1] == '\r')
            raw[0 .. raw.len - 1]
        else
            raw;
        try lines.append(arena, stripped);
    }

    var pos: usize = 0;
    return parseValue(arena, lines.items, &pos, 0);
}

fn parseValue(
    arena: std.mem.Allocator,
    lines: [][]const u8,
    pos: *usize,
    min_indent: usize,
) ParseError!Node {
    skipBlanks(lines, pos);
    if (pos.* >= lines.len) return Node{ .scalar = "" };

    const line = lines[pos.*];
    const indent = countIndent(line);
    if (indent < min_indent) return Node{ .scalar = "" };

    const trimmed = line[indent..];
    if (trimmed.len == 0) return Node{ .scalar = "" };

    if (isSequenceMarker(trimmed)) {
        return parseSequence(arena, lines, pos, indent);
    }
    if (std.mem.indexOfScalar(u8, trimmed, ':') != null and !looksLikeUrl(trimmed)) {
        return parseMapping(arena, lines, pos, indent);
    }
    pos.* += 1;
    return Node{ .scalar = stripInlineComment(trimmed) };
}

fn parseMapping(
    arena: std.mem.Allocator,
    lines: [][]const u8,
    pos: *usize,
    indent: usize,
) ParseError!Node {
    var entries: std.ArrayList(Kv) = .empty;
    while (true) {
        skipBlanks(lines, pos);
        if (pos.* >= lines.len) break;
        const line = lines[pos.*];
        const this_indent = countIndent(line);
        if (this_indent != indent) break;
        const trimmed = line[indent..];
        if (trimmed.len == 0 or trimmed[0] == '-') break;

        const colon = std.mem.indexOfScalar(u8, trimmed, ':') orelse break;
        const key = unquote(std.mem.trim(u8, trimmed[0..colon], " \t"));
        const after = std.mem.trimStart(u8, trimmed[colon + 1 ..], " \t");
        pos.* += 1;

        const value = try parseInlineOrBlockValue(arena, lines, pos, indent, after);
        try entries.append(arena, .{
            .key = try arena.dupe(u8, key),
            .value = value,
        });
    }
    return Node{ .mapping = try entries.toOwnedSlice(arena) };
}

fn parseSequence(
    arena: std.mem.Allocator,
    lines: [][]const u8,
    pos: *usize,
    indent: usize,
) ParseError!Node {
    var items: std.ArrayList(Node) = .empty;
    while (true) {
        skipBlanks(lines, pos);
        if (pos.* >= lines.len) break;
        const line = lines[pos.*];
        const this_indent = countIndent(line);
        if (this_indent != indent) break;
        const trimmed = line[indent..];
        if (!isSequenceMarker(trimmed)) break;

        const after = if (trimmed.len == 1)
            ""
        else
            std.mem.trimStart(u8, trimmed[1..], " \t");

        if (after.len == 0) {
            // `-` alone: the value is on subsequent indented lines.
            pos.* += 1;
            const value = try parseValue(arena, lines, pos, indent + 2);
            try items.append(arena, value);
            continue;
        }

        // Compact-mapping-after-dash: `- key: value`. The mapping's first
        // entry is the key/value after the dash; subsequent entries (if
        // any) are at indent = indent + 2 (one level deeper than the dash).
        if (std.mem.indexOfScalar(u8, after, ':') != null and !looksLikeUrl(after)) {
            const map_indent = indent + 2;
            const colon = std.mem.indexOfScalar(u8, after, ':').?;
            const key = unquote(std.mem.trim(u8, after[0..colon], " \t"));
            const tail = std.mem.trimStart(u8, after[colon + 1 ..], " \t");
            pos.* += 1;

            var entries: std.ArrayList(Kv) = .empty;
            const first_value = try parseInlineOrBlockValue(
                arena, lines, pos, map_indent, tail,
            );
            try entries.append(arena, .{
                .key = try arena.dupe(u8, key),
                .value = first_value,
            });

            // Continuation: pull additional entries at exactly map_indent
            // until we hit something else.
            while (true) {
                skipBlanks(lines, pos);
                if (pos.* >= lines.len) break;
                const cur = lines[pos.*];
                const cur_indent = countIndent(cur);
                if (cur_indent != map_indent) break;
                const cur_trimmed = cur[map_indent..];
                if (cur_trimmed.len == 0 or cur_trimmed[0] == '-') break;
                const c2 = std.mem.indexOfScalar(u8, cur_trimmed, ':') orelse break;
                if (looksLikeUrl(cur_trimmed)) break;
                const k2 = unquote(std.mem.trim(u8, cur_trimmed[0..c2], " \t"));
                const t2 = std.mem.trimStart(u8, cur_trimmed[c2 + 1 ..], " \t");
                pos.* += 1;
                const v2 = try parseInlineOrBlockValue(
                    arena, lines, pos, map_indent, t2,
                );
                try entries.append(arena, .{
                    .key = try arena.dupe(u8, k2),
                    .value = v2,
                });
            }

            try items.append(arena, Node{ .mapping = try entries.toOwnedSlice(arena) });
            continue;
        }

        // Plain scalar after dash.
        pos.* += 1;
        try items.append(arena, Node{ .scalar = try arena.dupe(u8, stripInlineComment(after)) });
    }
    return Node{ .sequence = try items.toOwnedSlice(arena) };
}

fn parseInlineOrBlockValue(
    arena: std.mem.Allocator,
    lines: [][]const u8,
    pos: *usize,
    parent_indent: usize,
    after: []const u8,
) ParseError!Node {
    if (after.len == 0) {
        // Block-style child. Sequence-at-same-indent is allowed as a value
        // (the YAML compact idiom); nested mappings must be deeper.
        skipBlanks(lines, pos);
        if (pos.* >= lines.len) return Node{ .scalar = "" };
        const next = lines[pos.*];
        const ni = countIndent(next);
        if (ni == parent_indent) {
            const trimmed = next[ni..];
            if (isSequenceMarker(trimmed)) {
                return parseSequence(arena, lines, pos, parent_indent);
            }
            return Node{ .scalar = "" };
        }
        if (ni > parent_indent) {
            return parseValue(arena, lines, pos, ni);
        }
        return Node{ .scalar = "" };
    }
    if (after[0] == '|' or after[0] == '>') {
        // Block scalar. The body lines must be indented more than parent.
        return Node{
            .scalar = try parseBlockScalar(arena, lines, pos, parent_indent),
        };
    }
    return Node{ .scalar = try arena.dupe(u8, unquote(stripInlineComment(after))) };
}

fn parseBlockScalar(
    arena: std.mem.Allocator,
    lines: [][]const u8,
    pos: *usize,
    parent_indent: usize,
) ParseError![]const u8 {
    // The body indent is the indent of the first non-empty body line. It
    // must be > parent_indent. Empty lines mid-block are preserved as
    // newlines. We strip body_indent from each line.
    var body_indent: ?usize = null;
    var buf: std.ArrayList(u8) = .empty;
    var first_written = false;

    while (pos.* < lines.len) {
        const line = lines[pos.*];
        const trimmed = std.mem.trimStart(u8, line, " \t");
        if (trimmed.len == 0) {
            // Blank line: include as newline iff we've already started
            // and we haven't reached EOF without further body lines.
            if (first_written) {
                try buf.append(arena, '\n');
            }
            pos.* += 1;
            continue;
        }
        const li = countIndent(line);
        if (li <= parent_indent) break;
        if (body_indent == null) body_indent = li;
        if (li < body_indent.?) break;

        if (first_written) try buf.append(arena, '\n');
        try buf.appendSlice(arena, line[body_indent.?..]);
        first_written = true;
        pos.* += 1;
    }
    // Trim trailing whitespace/newlines for cleanliness — ART atomics
    // typically have a single trailing newline in their command blocks.
    var out = buf.items;
    while (out.len > 0 and (out[out.len - 1] == '\n' or out[out.len - 1] == ' ' or out[out.len - 1] == '\t')) {
        out = out[0 .. out.len - 1];
    }
    return try arena.dupe(u8, out);
}

fn skipBlanks(lines: [][]const u8, pos: *usize) void {
    while (pos.* < lines.len) {
        const line = lines[pos.*];
        const trimmed = std.mem.trimStart(u8, line, " \t");
        if (trimmed.len == 0 or trimmed[0] == '#') {
            pos.* += 1;
            continue;
        }
        break;
    }
}

fn countIndent(line: []const u8) usize {
    var i: usize = 0;
    while (i < line.len and line[i] == ' ') : (i += 1) {}
    return i;
}

fn isSequenceMarker(trimmed: []const u8) bool {
    if (trimmed.len == 0) return false;
    if (trimmed[0] != '-') return false;
    if (trimmed.len == 1) return true;
    return trimmed[1] == ' ' or trimmed[1] == '\t';
}

/// Heuristic: `key: value` where `value` looks like a URL (`http://`,
/// `https://`) shouldn't be confused with a deeper mapping. ART atomics
/// often have URLs in `description` fields.
fn looksLikeUrl(s: []const u8) bool {
    if (std.mem.indexOf(u8, s, "://") == null) return false;
    const colon = std.mem.indexOfScalar(u8, s, ':') orelse return false;
    if (colon + 2 >= s.len) return false;
    return s[colon + 1] == '/' and s[colon + 2] == '/';
}

fn stripInlineComment(s: []const u8) []const u8 {
    var in_q: ?u8 = null;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        const c = s[i];
        if (in_q) |q| {
            if (c == q) in_q = null;
        } else {
            if (c == '\'' or c == '"') in_q = c;
            // '#' as a comment marker requires preceding whitespace per the
            // YAML spec; we honor that to avoid eating literal `#` chars
            // inside unquoted scalars.
            if (c == '#' and (i == 0 or s[i - 1] == ' ' or s[i - 1] == '\t')) {
                return std.mem.trim(u8, s[0..i], " \t");
            }
        }
    }
    return std.mem.trim(u8, s, " \t");
}

fn unquote(s: []const u8) []const u8 {
    if (s.len < 2) return s;
    if ((s[0] == '"' and s[s.len - 1] == '"') or
        (s[0] == '\'' and s[s.len - 1] == '\''))
    {
        return s[1 .. s.len - 1];
    }
    return s;
}

// ─── Tests ──────────────────────────────────────────────────────────────────

test "parse: flat mapping" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const src =
        \\name: foo
        \\age: 42
        \\active: true
    ;
    const root = try parse(a, src);
    try std.testing.expect(root == .mapping);
    try std.testing.expectEqualStrings("foo", root.lookup("name").?.scalar);
    try std.testing.expectEqualStrings("42", root.lookup("age").?.scalar);
    try std.testing.expectEqualStrings("true", root.lookup("active").?.scalar);
}

test "parse: nested mapping" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const src =
        \\outer:
        \\  inner: hello
        \\  count: 7
    ;
    const root = try parse(a, src);
    const inner = root.lookup("outer").?;
    try std.testing.expect(inner == .mapping);
    try std.testing.expectEqualStrings("hello", inner.lookup("inner").?.scalar);
}

test "parse: flat sequence" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const src =
        \\- linux
        \\- macos
        \\- windows
    ;
    const root = try parse(a, src);
    try std.testing.expect(root == .sequence);
    try std.testing.expect(root.sequence.len == 3);
    try std.testing.expectEqualStrings("linux", root.sequence[0].scalar);
}

test "parse: sequence-as-value of mapping at same indent (compact form)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const src =
        \\platforms:
        \\- linux
        \\- macos
    ;
    const root = try parse(a, src);
    const platforms = root.lookup("platforms").?;
    try std.testing.expect(platforms == .sequence);
    try std.testing.expect(platforms.sequence.len == 2);
}

test "parse: sequence-of-mappings" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const src =
        \\tests:
        \\- name: first
        \\  command: echo 1
        \\- name: second
        \\  command: echo 2
    ;
    const root = try parse(a, src);
    const tests = root.lookup("tests").?;
    try std.testing.expect(tests == .sequence);
    try std.testing.expect(tests.sequence.len == 2);
    try std.testing.expectEqualStrings("first", tests.sequence[0].lookup("name").?.scalar);
    try std.testing.expectEqualStrings("echo 2", tests.sequence[1].lookup("command").?.scalar);
}

test "parse: block scalar literal preserves newlines" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const src =
        \\command: |
        \\  echo hello
        \\  echo world
    ;
    const root = try parse(a, src);
    const cmd = root.lookup("command").?.scalar;
    try std.testing.expectEqualStrings("echo hello\necho world", cmd);
}

test "parse: comments and blank lines ignored" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const src =
        \\# comment
        \\name: foo  # trailing comment
        \\
        \\age: 42
    ;
    const root = try parse(a, src);
    try std.testing.expectEqualStrings("foo", root.lookup("name").?.scalar);
    try std.testing.expectEqualStrings("42", root.lookup("age").?.scalar);
}

test "parse: quoted strings stripped" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const src =
        \\dq: "hello world"
        \\sq: 'foo bar'
    ;
    const root = try parse(a, src);
    try std.testing.expectEqualStrings("hello world", root.lookup("dq").?.scalar);
    try std.testing.expectEqualStrings("foo bar", root.lookup("sq").?.scalar);
}

test "parse: ART-shaped atomic" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const src =
        \\attack_technique: T1082
        \\display_name: System Information Discovery
        \\atomic_tests:
        \\- name: System Information Discovery
        \\  description: |
        \\    Identify System Info via uname.
        \\  supported_platforms:
        \\  - linux
        \\  - macos
        \\  executor:
        \\    command: |
        \\      uname -a
        \\      cat /etc/os-release
        \\    name: bash
        \\    elevation_required: false
    ;
    const root = try parse(a, src);
    try std.testing.expectEqualStrings("T1082", root.lookup("attack_technique").?.scalar);
    const tests = root.lookup("atomic_tests").?;
    try std.testing.expect(tests.sequence.len == 1);
    const t0 = tests.sequence[0];
    try std.testing.expectEqualStrings("System Information Discovery", t0.lookup("name").?.scalar);
    const exec = t0.lookup("executor").?;
    try std.testing.expectEqualStrings("bash", exec.lookup("name").?.scalar);
    try std.testing.expectEqualStrings(
        "uname -a\ncat /etc/os-release",
        exec.lookup("command").?.scalar,
    );
    const platforms = t0.lookup("supported_platforms").?;
    try std.testing.expect(platforms.sequence.len == 2);
    try std.testing.expectEqualStrings("linux", platforms.sequence[0].scalar);
    try std.testing.expectEqualStrings("macos", platforms.sequence[1].scalar);
}
