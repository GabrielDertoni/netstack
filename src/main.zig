//
// God dammit get packed structs working! I had to change the whole way I was doing stuff to a
// worse way simply because I couldn't get the compiler to work with packed structs without crasing
// all the time!
//

const c = @cImport({
    @cInclude("unistd.h");
    @cInclude("netinet/ether.h");
    @cInclude("netinet/ip_icmp.h");
});

const std = @import("std");
const mem = std.mem;
const os = std.os;

const native_endian = @import("builtin").target.cpu.arch.endian();
const print = std.debug.print;
const assert = std.debug.assert;

const ethernet = @import("./ethernet.zig");

const TunDevice = @import("./tuntap.zig").TunDevice;

const util = @import("./util.zig");
const DevAddress = util.DevAddress;

pub fn main() !void {
    var iface = try TunDevice.init("tun0");
    defer iface.deinit();

    print("Running...\n", .{});

    const addr = DevAddress{
        .ip = try util.parseIp("10.0.0.2"),
        .mac = try util.parseMac("00:0c:29:6d:50:25"),
    };

    var buf: [1024]u8 = undefined;
    while (true) {
        var nbytes = try iface.read(&buf);
        try ethernet.handleEthernet(&iface, addr, buf[0..nbytes]);
    }
}
