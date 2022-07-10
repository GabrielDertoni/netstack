const std = @import("std");

const bin_name = "netstack";

pub fn build(b: *std.build.Builder) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    const exe = b.addExecutable(bin_name, "src/main.zig");
    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.addCSourceFile("src/c_zig_interop/c_zig_interop.c", &.{});
    exe.addIncludeDir("src/c_zig_interop");
    exe.linkLibC();
    // exe.single_threaded = true;
    exe.install();

    const set_perm = SetPermStep.create(b);
    set_perm.step.dependOn(b.getInstallStep());

    const set_perm_cmd = b.step("perm", "Build and set permissions for exe");
    set_perm_cmd.dependOn(&set_perm.step);

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.step.dependOn(&set_perm.step);
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const exe_tests = b.addTest("src/main.zig");
    exe_tests.setTarget(target);
    exe_tests.setBuildMode(mode);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&exe_tests.step);
}

const SetPermStep = struct {
    pub const base_id = .custom;

    builder: *std.build.Builder,
    step: std.build.Step,

    const Self = @This();

    fn create(builder: *std.build.Builder) *Self {
        var self = builder.allocator.create(Self) catch unreachable;
        self.builder = builder;
        self.step = std.build.Step.init(.custom, "perm", builder.allocator, setPermission);
        return self;
    }

    fn setPermission(step: *std.build.Step) anyerror!void {
        var self = step.cast(Self).?;

        var allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer allocator.deinit();

        // sudo setcap cap_net_admin=eip zig-out/bin/netstack

        const bin_path = self.builder.getInstallPath(.bin, bin_name);
        const term = try std.ChildProcess.init(
            &.{ "/usr/bin/sudo", "/usr/sbin/setcap", "cap_net_admin=eip", bin_path },
            allocator.allocator(),
        ).spawnAndWait();

        switch (term) {
            .Exited => |code| if (code != 0) return error.ChildProcessExitFailure else {},
            else => return error.ChildProcessExitedUnexpectedly,
        }
    }
};
