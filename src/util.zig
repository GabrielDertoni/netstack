const std = @import("std");
const mem = std.mem;
const io = std.io;
const os = std.os;
const event = std.event;
const native_endian = @import("builtin").target.cpu.arch.endian();

pub const DevAddress = struct {
    ip: u32,
    mac: u48,
};

pub const SliceWriterError = error{
    SliceFull,
};

pub fn writeToSlice(self: *[]u8, buf: []const u8) SliceWriterError!usize {
    if (self.*.len == 0) return SliceWriterError.SliceFull;
    var count = @minimum(self.*.len, buf.len);
    @memcpy(self.*.ptr, buf.ptr, count);
    self.* = self.*[count..];
    return count;
}

pub const SliceWriter = io.Writer(*[]u8, SliceWriterError, writeToSlice);

pub fn sliceWriter(slice: *[]u8) SliceWriter {
    return SliceWriter{ .context = slice };
}

pub fn internetChecksum(bytes: []const u8) u16 {
    // source: https://datatracker.ietf.org/doc/html/rfc1071

    var count: usize = bytes.len;
    var slice: []const u8 = bytes;
    var sum: u32 = 0;

    while (count > 1) {
        sum += mem.readIntBig(u16, slice[0..2]);
        slice = slice[2..];
        count -= 2;
    }

    if (count > 0) sum += slice[0];
    while ((sum >> 16) != 0) sum = (sum & 0xffff) + (sum >> 16);

    return @truncate(u16, ~sum);
}

pub const IpParseError = error{
    InvalidAddress,
};

pub fn parseIp(ip: []const u8) IpParseError!u32 {
    var addr: u32 = 0;

    var segment_slice: []const u8 = undefined;
    segment_slice.ptr = ip.ptr;
    segment_slice.len = 0;

    var dot_count: u32 = 0;
    for (ip) |char| {
        switch (char) {
            '0'...'9' => segment_slice.len += 1,
            '.' => {
                if (dot_count == 3) return error.InvalidAddress;
                const v = std.fmt.parseInt(u8, segment_slice, 10) catch return error.InvalidAddress;
                addr <<= 8;
                addr |= v;
                segment_slice.ptr = segment_slice.ptr + segment_slice.len + 1;
                segment_slice.len = 0;

                dot_count += 1;
            },
            else => return error.InvalidAddress,
        }
    }

    if (dot_count != 3) return error.InvalidAddress;
    const v = std.fmt.parseInt(u8, segment_slice, 10) catch return error.InvalidAddress;
    addr <<= 8;
    addr |= v;

    return addr;
}

pub fn parseMac(str: []const u8) std.fmt.ParseIntError!u48 {
    const parseUnsigned = std.fmt.parseUnsigned;
    var result: [6]u8 = undefined;
    var i: usize = 0;
    var slice = str;
    while (i < 6) {
        defer i += 1;
        result[i] = try parseUnsigned(u8, slice[0..2], 16);
        // Skip the ':' character as well.
        if (slice.len >= 3) slice = slice[3..];
    }
    return mem.readIntBig(u48, &result);
}

pub fn macAddrToStr(mac: u48) [18:0]u8 {
    var s: [18:0]u8 = undefined;

    var slice: []u8 = &s;
    var writer = sliceWriter(&slice);

    var mac_bytes = @ptrCast(*const [6]u8, &mac);
    for (mac_bytes) |byte, i| {
        // The buffer should have enough space to fit the whole thing
        if (i > 0) writer.print(":", .{}) catch unreachable;
        writer.print("{x:0<2}", .{byte}) catch unreachable;
    }

    s[17] = 0;
    return s;
}

pub fn runCmdSync(cmd: []const u8) !void {
    var arena_alloc = std.heap.ArenaAllocator.init(std.heap.c_allocator);
    defer arena_alloc.deinit();
    const arena = arena_alloc.allocator();

    const argv: []const []const u8 = &.{ "/bin/sh", "-c", cmd };
    const argv_buf = try arena.allocSentinel(?[*:0]u8, argv.len, null);
    for (argv) |arg, i| argv_buf[i] = (try arena.dupeZ(u8, arg)).ptr;

    const envp = try arena.allocSentinel(?[*:0]const u8, 0, null);

    const pid_result = try os.fork();
    if (pid_result == 0) {
        os.execvpeZ_expandArg0(.expand, argv_buf.ptr[0].?, argv_buf.ptr, envp) catch {};
        os.exit(1);
    }
    const ret = os.waitpid(pid_result, 0);
    if (ret.status != 0) return error.CmdFailed;
}

pub fn waitFdTimeout(fd: os.fd_t, events: u32, timeout_ns: u64) !void {
    if (std.io.mode != .evented) @compileError("only works in evented mode");

    const timerfd = try os.timerfd_create(os.CLOCK.REALTIME, 0);
    defer os.close(timerfd);

    const timerspec = os.linux.itimerspec{
        .it_interval = os.linux.timespec{ .tv_sec = 0, .tv_nsec = 0 },
        .it_value = os.linux.timespec{
            .tv_sec = @intCast(isize, timeout_ns / std.time.ns_per_s),
            .tv_nsec = @intCast(isize, timeout_ns % std.time.ns_per_s),
        },
    };
    try os.timerfd_settime(timerfd, 0, &timerspec, null);

    const epollfd = try os.epoll_create1(os.linux.EPOLL.CLOEXEC);
    defer os.close(epollfd);

    var timerfd_event = os.linux.epoll_event{
        .events = os.linux.EPOLL.IN,
        .data = os.linux.epoll_data{ .fd = timerfd },
    };
    try os.epoll_ctl(epollfd, os.linux.EPOLL.CTL_ADD, timerfd, &timerfd_event);

    var fd_event = os.linux.epoll_event{
        .events = events,
        .data = os.linux.epoll_data{ .fd = fd },
    };
    try os.epoll_ctl(epollfd, os.linux.EPOLL.CTL_ADD, fd, &fd_event);

    event.Loop.instance.?.waitUntilFdReadable(epollfd);

    // We know that some event occurred, so this should always just return the event that happened.
    var revents: [2]os.linux.epoll_event = undefined;
    const nevents = os.epoll_wait(epollfd, &revents, 0);
    if (nevents == 0) return error.Unexpected;
    if (nevents == 1 and revents[0].data.fd == timerfd) return error.Timeout;
}
