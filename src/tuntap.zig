const c = @cImport({
    @cInclude("c_zig_interop.h");

    @cInclude("linux/if.h");
});

const std = @import("std");
const os = std.os;
const io = std.io;
const event = std.event;

pub const TunDevice = struct {
    name: [c.IFNAMSIZ:0]u8,
    fd: os.fd_t,

    const Self = @This();
    const Reader = io.Reader(*Self, os.ReadError, read);
    const Writer = io.Writer(*Self, os.WriteError, write);

    pub fn init(dev_name: []const u8) !Self {
        var name: [c.IFNAMSIZ:0]u8 = undefined;
        @memset(&name, 0, c.IFNAMSIZ);
        @memcpy(&name, dev_name.ptr, @minimum(@intCast(usize, c.IFNAMSIZ), dev_name.len));

        var fd = if (io.mode == .evented) c.tun_alloc_nonblock(&name) else c.tun_alloc(&name);
        if (fd < 0) return error.FailedTunAlloc;
        return Self{ .name = name, .fd = fd };
    }

    pub fn deinit(self: *Self) void {
        os.close(self.fd);
    }

    pub fn read(self: *Self, buf: []u8) os.ReadError!usize {
        if (io.mode == .evented) {
            // Not simulating the event loop, we want the real thing!
            return event.Loop.instance.?.read(self.fd, buf, false);
        } else {
            return os.read(self.fd, buf);
        }
    }

    pub fn write(self: *Self, buf: []const u8) os.WriteError!usize {
        if (io.mode == .evented) {
            // Not simulating the event loop, we want the real thing!
            return event.Loop.instance.?.write(self.fd, buf, false);
        } else {
            return os.write(self.fd, buf);
        }
    }

    pub fn reader(self: *Self) Reader {
        return Reader{ .context = self };
    }

    pub fn writer(self: *Self) Writer {
        return Writer{ .context = self };
    }
};
