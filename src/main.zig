//
// God dammit get packed structs working! I had to change the whole way I was doing stuff to a
// worse way simply because I couldn't get the compiler to work with packed structs without crasing
// all the time!
//

const c = @cImport({
    @cInclude("unistd.h");
    @cInclude("linux/if_ether.h");
    @cInclude("linux/if_arp.h");
    @cInclude("arpa/inet.h");
});

const std = @import("std");
const mem = std.mem;

const native_endian = @import("builtin").target.cpu.arch.endian();
const print = std.debug.print;
const assert = std.debug.assert;

const gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();

const ethernet = @import("./ethernet.zig");
const EthernetHeaderPtr = ethernet.EthernetHeaderPtr;
const mac_addr_to_str = ethernet.mac_addr_to_str;

const TunDevice = @import("./tuntap.zig").TunDevice;

const handle_arp = @import("./arp.zig").handle_arp;

const util = @import("./util.zig");
const sepByWriter = util.sepByWriter;
const sliceWriter = util.sliceWriter;

pub fn main() !void {
    var iface = try TunDevice.init("tun0");
    defer iface.deinit();

    print("Running...\n", .{});

    var stdout = std.io.getStdOut().writer();
    const ip = try parse_ip("10.0.0.2");
    const mac = try parse_mac("00:0c:29:6d:50:25");

    var buf: [1024]u8 = undefined;
    while (true) {
        var nbytes = try iface.read(&buf);

        var ether = EthernetHeaderPtr.cast(buf[0..nbytes]);
        const ethertype = ether.ethertype();
        // if (ethertype != c.ETH_P_ARP and ethertype != c.ETH_P_IP) continue;

        print("\nbytes received: [", .{});
        var w = sepByWriter(stdout, ", ").writer();
        for (buf[0..nbytes]) |byte| try w.print("{x:0<2}", .{byte});
        print("]\n", .{});

        if (ethertype == c.ETH_P_ARP) {
            print("ARP frame\n", .{});
        } else if (ethertype == c.ETH_P_IP) {
            print("IP frame\n", .{});
        }

        if (ethertype == c.ETH_P_ARP) {
            _ = handle_arp(&iface, ip, mac, buf[EthernetHeaderPtr.Size..]) catch {};
        }
    }
}

const IpParseError = error{
    InvalidAddress,
    NotSupported,
};

fn parse_ip(ip: [*:0]const u8) IpParseError!u32 {
    var addr: u32 = undefined;
    const ret = c.inet_pton(c.AF_INET, ip, @ptrCast(?*anyopaque, &addr));
    if (ret == 0) return IpParseError.InvalidAddress;
    if (ret < 0) return IpParseError.NotSupported;
    return switch (native_endian) {
        .Big => addr,
        .Little => @byteSwap(u32, addr),
    };
}

fn parse_mac(str: []const u8) std.fmt.ParseIntError!u48 {
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
