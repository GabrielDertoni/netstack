const c = @cImport(@cInclude("netinet/ip_icmp.h"));

const std = @import("std");
const mem = std.mem;
const print = std.debug.print;
const assert = std.debug.assert;

const ethernet = @import("./ethernet.zig");
const EthernetHeaderPtr = ethernet.EthernetHeaderPtr;

const ip = @import("./ip.zig");
const IPv4PDU = ip.IPv4PDU;
const IpHeaderPtr = ip.IpHeaderPtr;
const TunDevice = @import("./tuntap.zig").TunDevice;

const util = @import("./util.zig");
const DevAddress = util.DevAddress;

const SendBuf = @import("./buf.zig").SendBuf;

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
var allocator = gpa.allocator();

pub const ICMPv4PDU = struct {
    prev: IPv4PDU,
    header: ICMPv4HeaderPtr,
    sdu: []u8,
};

pub const ICMPv4HeaderPtr = struct {
    data: *[Size]u8,

    // type           - 8 bits
    // code           - 8 bits
    // checksum       - 16 bits
    // rest_of_header - 32 bits
    //                  -------
    //                  64 bits
    //                   8 bytes
    pub const Size = 8;
    const Self = @This();

    pub fn cast(buf: []u8) Self {
        assert(buf.len >= Size);
        return Self{ .data = buf[0..Size] };
    }

    // Here, the type field communicates the purpose of the message. 42 different8 values are
    // reserved for the type field, but only about 8 are commonly used. In our implementation, the
    // types 0 (Echo Reply), 3 (Destination Unreachable) and 8 (Echo request) are used.
    pub fn @"type"(self: Self) u8 {
        return self.data[0];
    }

    pub fn setType(self: Self, val: u8) void {
        self.data[0] = val;
    }

    // The code field further describes the meaning of the message. For example, when the type is 3
    // (Destination Unreachable), the code-field implies the reason. A common error is when a
    // packet cannot be routed to a network: the originating host then most likely receives an ICMP
    // message with the type 3 and code 0 (Net Unreachable).
    pub fn code(self: Self) u8 {
        return self.data[1];
    }

    pub fn setCode(self: Self, val: u8) void {
        self.data[1] = val;
    }

    // The csum field is the same checksum field as in the IPv4 header, and the same algorithm can
    // be used to calculate it. In ICMPv4 however, the checksum is end-to-end, meaning that also
    // the payload is included when calculating the checksum.
    pub fn checksum(self: Self) u16 {
        return mem.readIntBig(u16, self.data[2..4]);
    }

    pub fn setChecksum(self: Self, val: u16) void {
        mem.writeIntBig(u16, self.data[2..4], val);
    }

    pub fn restOfHeader(self: Self) *[4]u8 {
        return self.data[4..8];
    }

    pub fn set(self: Self, val: anytype) void {
        const T = @TypeOf(val);

        const info = @typeInfo(T);
        const struct_info = switch (info) {
            .Struct => |i| i,
            else => @compileError("val must be a struct"),
        };
        inline for (struct_info.fields) |field| {
            if (comptime mem.eql(u8, field.name, "type")) {
                self.setType(val.type);
            } else if (comptime mem.eql(u8, field.name, "code")) {
                self.setCode(val.code);
            } else if (comptime mem.eql(u8, field.name, "checksum")) {
                self.setChecksum(val.checksum);
            } else {
                @compileError("unexpected field " ++ field.name);
            }
        }
    }
};

pub const ICMPv4EchoPtr = struct {
    data: *[Size]u8,
    pkt_len: usize,

    // id  - 16 bits
    // seq - 16 bits
    //       -------
    //       32 bits
    //        4 bytes
    pub const Size = 4;
    const Self = @This();

    // `buf` should be the entire ICMPv4 echo packet.
    pub fn cast(buf: []u8) Self {
        assert(buf.len >= Size);
        return Self{ .data = buf[0..Size], .pkt_len = buf.len };
    }

    // The field id is set by the sending host to determine to which process the echo reply is
    // intended. For example, the process id can be set in to this field.
    pub fn id(self: Self) u16 {
        return mem.readIntBig(u16, self.data[0..2]);
    }

    pub fn set_id(self: Self, val: u16) void {
        mem.writeIntBig(u16, self.data[0..2], val);
    }

    // The field seq is the sequence number of the echo and it is simply a number starting from
    // zero and incremented by one whenever a new echo request is formed. This is used to detect if
    // echo messages disappear or are reordered while in transit.
    pub fn seq(self: Self) u16 {
        return mem.readIntBig(u16, self.data[2..4]);
    }

    pub fn set_seq(self: Self, val: u16) void {
        mem.writeIntBig(u16, self.data[2..4], val);
    }

    // The data field is optional, but often contains information like the timestamp of the echo.
    // This can then be used to estimate the round-trip time between hosts.
    pub fn trailing_data(self: Self) []u8 {
        var slice: []u8 = undefined;
        slice.ptr = @ptrCast([*]u8, self.data);
        slice.len = self.pkt_len;
        return slice[Size..];
    }

    pub fn set(self: Self, val: anytype) void {
        const T = @TypeOf(val);

        const info = @typeInfo(T);
        const struct_info = switch (info) {
            .Struct => |i| i,
            else => @compileError("val must be a struct"),
        };
        inline for (struct_info.fields) |field| {
            if (comptime mem.eql(u8, field.name, "id")) {
                self.set_id(val.id);
            } else if (comptime mem.eql(u8, field.name, "seq")) {
                self.set_seq(val.seq);
            } else {
                @compileError("unexpected field " ++ field.name);
            }
        }
    }
};

pub const ICMPv4DestUnreachable = struct {
    data: *[Size]u8,

    // TODO: Remove since `len()` should already provide this info.
    pkt_len: usize,

    // unused -  8 bits
    // len    -  8 bits
    // var    - 16 bits
    //          -------
    //          32 bits
    //           4 bytes
    pub const Size = 4;
    const Self = @This();

    pub fn cast(buf: []u8) Self {
        assert(buf.len >= Size);
        return Self{ .data = buf, .pkt_len = buf.len };
    }

    pub fn len(self: Self) u8 {
        return self.data[1];
    }

    pub fn set_len(self: Self, val: u8) void {
        self.data[1] = val;
    }

    // Then, the len field indicates the length of the original datagram, in 4-octet units for IPv4.
    pub fn @"var"(self: Self) u16 {
        return mem.readIntBig(u16, self.data[2..4]);
    }

    // The value of the 2-octet field var depends on the ICMP code.
    pub fn set_var(self: Self, val: u16) void {
        mem.writeIntBig(u16, self.data[2..4], val);
    }

    // Finally, as much as possible of the original IP packet that caused the Destination
    // Unreachable state is placed into the data field.
    pub fn trailing_data(self: Self) []u8 {
        var slice: []u8 = undefined;
        slice.ptr = @ptrCast([*]u8, self.data);
        slice.len = self.len - Size;
        return slice[Size..];
    }
};

pub fn handleICMP(iface: *TunDevice, addr: DevAddress, prev: IPv4PDU) !void {
    const data = prev.sdu;
    const icmp_hdr = ICMPv4HeaderPtr.cast(data);
    const pdu = ICMPv4PDU{
        .prev = prev,
        .header = icmp_hdr,
        .sdu = data[ICMPv4HeaderPtr.Size..],
    };
    _ = pdu;

    if (icmp_hdr.@"type"() != c.ICMP_ECHO) {
        print("Received an unexpected icmp packed", .{});
        return;
    }

    const icmp_echo = ICMPv4EchoPtr.cast(icmp_hdr.restOfHeader());
    _ = icmp_echo;

    icmp_hdr.setType(c.ICMP_ECHOREPLY);
    icmp_hdr.setChecksum(0);
    icmp_hdr.setChecksum(util.internetChecksum(data));

    var buf = SendBuf.init(allocator);
    defer buf.deinit();

    try buf.reserve(EthernetHeaderPtr.Size + IpHeaderPtr.size + ICMPv4HeaderPtr.Size + pdu.sdu.len);

    var icmp_data_buf = try buf.allocSlot(pdu.sdu.len);
    std.mem.copy(u8, icmp_data_buf, pdu.sdu);

    var icmp_buf = try buf.allocSlot(ICMPv4HeaderPtr.Size);
    var icmp_hdr_reply = ICMPv4HeaderPtr.cast(icmp_buf);
    icmp_hdr_reply.set(.{
        .type = c.ICMP_ECHOREPLY,
        .checksum = 0,
    });
    std.mem.copy(u8, icmp_hdr_reply.restOfHeader(), icmp_echo.data);
    icmp_hdr_reply.setChecksum(util.internetChecksum(buf.slice()));

    try ip.replyIP(iface, addr, prev, &buf);
}
