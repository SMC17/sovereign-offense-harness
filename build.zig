const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "sovereign-offense-harness",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run sovereign-offense-harness");
    run_step.dependOn(&run_cmd.step);

    const test_step = b.step("test", "Run unit tests + safety-gate integration");
    const unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_tests = b.addRunArtifact(unit_tests);
    test_step.dependOn(&run_tests.step);

    // Subprocess-driven safety-gate integration test. Closes the M01-M03
    // mutation-testing findings (gate logic had no direct coverage).
    // Depends on the installed binary; the test script builds via `zig build`
    // internally as a no-op when artifacts are current.
    const integration_test = b.addSystemCommand(&.{
        "bash", "tests/safety_gate_integration.sh",
    });
    integration_test.step.dependOn(b.getInstallStep());
    test_step.dependOn(&integration_test.step);

    // Documentation tests — verify the README's executable claims hold
    // against the installed binary (documented subcommands + flags appear
    // in --help, the safety-gate refusal text matches the README quote,
    // and a benign --unsafe-local run produces the documented envelope
    // shape). Separate step from `test` because doctest is about README
    // drift, not gate behavior (that's safety_gate_integration.sh).
    const doctest = b.addSystemCommand(&.{ "bash", "tools/doctest.sh" });
    doctest.step.dependOn(b.getInstallStep());
    const doctest_step = b.step(
        "doctest",
        "Verify README's documented CLI surface + envelope shape match the binary",
    );
    doctest_step.dependOn(&doctest.step);
}
