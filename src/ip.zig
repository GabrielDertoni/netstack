const c = @cImport(@cInclude("netinet/ip.h"));

const std = @import("std");
const mem = std.mem;
const os = std.os;
const print = std.debug.print;
const assert = std.debug.assert;

const ethernet = @import("./ethernet.zig");
const EthernetPDU = ethernet.EthernetPDU;
const replyEthernet = ethernet.replyEthernet;

const icmp = @import("./icmp.zig");
const handleICMP = icmp.handleICMP;

const udp = @import("./udp.zig");
const handleUDP = udp.handleUDP;

const SendBuf = @import("./buf.zig").SendBuf;

const TunDevice = @import("./tuntap.zig").TunDevice;

const util = @import("./util.zig");
const DevAddress = util.DevAddress;

const packed_struct_ptr = @import("./packed_struct_ptr.zig");

pub const IPv4PDU = struct {
    prev: EthernetPDU,
    header: IpHeaderPtr,
    sdu: []u8,
};

pub const IpHeaderPtr = struct {
    data: *Inner.Data,

    pub const size = Inner.size;
    const Self = @This();
    const Inner = packed_struct_ptr.MakePackedStructPtr(.{
        .version = u4,
        .ihl = u4,
        .tos = u8,
        .len = u16,
        .id = u16,
        .flags = u3,
        .frag_offset = u13,
        .ttl = u8,
        .proto = u8,
        .header_checksum = u16,
        .sender_addr = u32,
        .dest_addr = u32,
    });

    pub fn cast(buf: []u8) Self {
        assert(buf.len >= Inner.size);
        return Self{ .data = buf[0..Inner.size] };
    }

    pub fn check(self: Self) !void {
        if (util.internetChecksum(self.data) != 0) return error.ChecksumFailed;
        if (self.getField(.ihl) != 5) return error.UnexpectedIpHeaderLength;
    }

    pub fn getField(self: Self, comptime field: Inner.Field) Inner.FieldTypeOf(field) {
        return Inner.getField(field, self.data);
    }

    pub fn setField(self: Self, comptime field: Inner.Field, val: Inner.FieldTypeOf(field)) void {
        Inner.setField(field, self.data, val);
    }

    pub fn set(self: Self, overwrites: anytype) void {
        Inner.set(overwrites, self.data);
    }

    pub fn compute_checksum(self: Self) void {
        self.setField(.header_checksum, 0);
        self.setField(.header_checksum, util.internetChecksum(self.data));
    }
};

// pub const IpHeaderPtr = struct {
//     data: *[Size]u8,
//
//     // version         -  4 bits
//     // ihl             -  4 bits
//     // tos             -  8 bits
//     // len             - 16 bits
//     // id              - 16 bits
//     // flags           -  3 bits
//     // frag_offset     - 13 bits
//     // ttl             -  8 bits
//     // proto           -  8 bits
//     // header_checksum - 16 bits
//     // sender_addr     - 32 bits
//     // dest_addr       - 32 bits
//     //                   -------
//     //                   160 bits
//     //                   20 bytes
//     pub const Size = 20;
//     const Self = @This();
//
//     pub fn cast(buf: []u8) Self {
//         assert(buf.len >= Size);
//         return Self{ .data = buf[0..Size] };
//     }
//
//     pub fn size(self: Self) u8 {
//         return @as(u8, self.ihl()) * 4;
//     }
//
//     pub fn version(self: Self) u4 {
//         return @truncate(u4, self.data[0] >> 4);
//     }
//
//     pub fn set_version(self: Self, val: u4) void {
//         self.data[0] &= 0x0f;
//         self.data[0] |= @as(u8, val) << 4;
//     }
//
//     // Internet Header Length - the number of 32-bit words in the IP header.
//     pub fn ihl(self: Self) u4 {
//         return @truncate(u4, self.data[0]);
//     }
//
//     pub fn set_ihl(self: Self, val: u4) void {
//         self.data[0] &= 0xf0;
//         self.data[0] |= @as(u8, val);
//     }
//
//     // Type Of Service - Communicates the Quality of Service (QoS) for the IP datagram.
//     pub fn tos(self: Self) u8 {
//         return self.data[1];
//     }
//
//     pub fn set_tos(self: Self, val: u8) void {
//         self.data[1] = val;
//     }
//
//     // The length of the **entire** IP datagram.
//     pub fn len(self: Self) u16 {
//         return mem.readIntBig(u16, self.data[2..4]);
//     }
//
//     pub fn set_len(self: Self, val: u16) void {
//         mem.writeIntBig(u16, self.data[2..4], val);
//     }
//
//     // Identifier for the fragment of the packet.
//     pub fn id(self: Self) u16 {
//         return mem.readIntBig(u16, self.data[4..6]);
//     }
//
//     pub fn set_id(self: Self, val: u16) void {
//         mem.writeIntBig(u16, self.data[4..6], val);
//     }
//
//     // Fragmentation flags, if the packet is allowed to fragment, etc.
//     pub fn flags(self: Self) u3 {
//         return @truncate(u3, self.data[6] >> 5);
//     }
//
//     pub fn set_flags(self: Self, val: u3) void {
//         self.data[6] &= ~(@as(u8, 0b111) << 5);
//         self.data[6] |= @as(u8, val) << 5;
//     }
//
//     // Offset of the fragmented packet. The first fragment will always have this field set to 0.
//     pub fn frag_offset(self: Self) u13 {
//         const val = mem.readIntBig(u16, self.data[6..8]);
//         return val & 0x1fff;
//     }
//
//     pub fn set_frag_offset(self: Self, val: u13) void {
//         const as_u16 = @as(u16, val);
//         const oldval = mem.readIntBig(u16, self.data[6..8]);
//         mem.writeIntBig(u16, self.data[6..8], (oldval & ~@as(u16, 0x1fff)) | as_u16);
//     }
//
//     // Time to Live. This value is generally set to 64 by the original sender and decremented by 1
//     // on each hop. When it hits 0, the packet is to be discarded and an ICMP message might be sent
//     // to indicate the error.
//     pub fn ttl(self: Self) u8 {
//         return self.data[8];
//     }
//
//     pub fn set_ttl(self: Self, val: u8) void {
//         self.data[8] = val;
//     }
//
//     // The identifier of the protocol transmitted in the packet. This value will typically be 16
//     // for UDP or 6 for TCP.
//     pub fn proto(self: Self) u8 {
//         return self.data[9];
//     }
//
//     pub fn set_proto(self: Self, val: u8) void {
//         self.data[9] = val;
//     }
//
//     // The header check sum verifies integrity of the _header_, not the packet as a whole.
//     pub fn header_checksum(self: Self) u16 {
//         return mem.readIntBig(u16, self.data[10..12]);
//     }
//
//     pub fn set_header_checksum(self: Self, val: u16) void {
//         mem.writeIntBig(u16, self.data[10..12], val);
//     }
//
//     // IP address of the sender.
//     pub fn sender_addr(self: Self) u32 {
//         return mem.readIntBig(u32, self.data[12..16]);
//     }
//
//     pub fn set_sender_addr(self: Self, val: u32) void {
//         mem.writeIntBig(u32, self.data[12..16], val);
//     }
//
//     // IP address of the destination.
//     pub fn dest_addr(self: Self) u32 {
//         return mem.readIntBig(u32, self.data[16..20]);
//     }
//
//     pub fn set_dest_addr(self: Self, val: u32) void {
//         mem.writeIntBig(u32, self.data[16..20], val);
//     }
//
//     pub fn as_slice(self: Self) *const [Size]u8 {
//         return self.data;
//     }
//
//     pub fn compute_checksum(self: Self) void {
//         self.set_header_checksum(0);
//         self.set_header_checksum(util.internetChecksum(self.data));
//     }
//
//     pub fn set(self: Self, val: anytype) void {
//         const T = @TypeOf(val);
//
//         const info = @typeInfo(T);
//         const struct_info = switch (info) {
//             .Struct => |i| i,
//             else => @compileError("val must be a struct"),
//         };
//         inline for (struct_info.fields) |field| {
//             if (comptime mem.eql(u8, field.name, "version")) {
//                 self.set_version(val.version);
//             } else if (comptime mem.eql(u8, field.name, "ihl")) {
//                 self.set_ihl(val.ihl);
//             } else if (comptime mem.eql(u8, field.name, "tos")) {
//                 self.set_tos(val.tos);
//             } else if (comptime mem.eql(u8, field.name, "len")) {
//                 self.set_len(val.len);
//             } else if (comptime mem.eql(u8, field.name, "id")) {
//                 self.set_id(val.id);
//             } else if (comptime mem.eql(u8, field.name, "flags")) {
//                 self.set_flags(val.flags);
//             } else if (comptime mem.eql(u8, field.name, "frag_offset")) {
//                 self.set_frag_offset(val.frag_offset);
//             } else if (comptime mem.eql(u8, field.name, "ttl")) {
//                 self.set_ttl(val.ttl);
//             } else if (comptime mem.eql(u8, field.name, "proto")) {
//                 self.set_proto(val.proto);
//             } else if (comptime mem.eql(u8, field.name, "header_checksum")) {
//                 self.set_header_checksum(val.header_checksum);
//             } else if (comptime mem.eql(u8, field.name, "sender_addr")) {
//                 self.set_sender_addr(val.sender_addr);
//             } else if (comptime mem.eql(u8, field.name, "dest_addr")) {
//                 self.set_dest_addr(val.dest_addr);
//             } else if (comptime mem.eql(u8, field.name, "header_checksum")) {
//                 self.set_header_checksum(val.header_checksum);
//             } else if (comptime mem.eql(u8, field.name, "sender_addr")) {
//                 self.set_sender_addr(val.sender_addr);
//             } else if (comptime mem.eql(u8, field.name, "dest_addr")) {
//                 self.set_dest_addr(val.dest_addr);
//             } else {
//                 @compileError("unexpected field " ++ field.name);
//             }
//         }
//     }
// };

pub fn handleIP(iface: *TunDevice, addr: DevAddress, prev: EthernetPDU) !void {
    const data = prev.sdu;
    const ip_hdr = IpHeaderPtr.cast(data);
    try ip_hdr.check();
    const pdu = IPv4PDU{
        .prev = prev,
        .header = ip_hdr,
        .sdu = data[IpHeaderPtr.size..],
    };

    if (ip_hdr.getField(.version) != 4) {
        print("Unexpected header version {d}\n", .{ip_hdr.getField(.version)});
        return;
    }

    const dest_addr = ip_hdr.getField(.dest_addr);
    if (dest_addr != addr.ip and dest_addr != 0xffffffff) {
        print("IP packet not for us", .{});
        return;
    }

    const proto = ip_hdr.getField(.proto);
    switch (proto) {
        os.IPPROTO.ICMP => {
            print("ICMPV4 packet\n", .{});
            _ = try handleICMP(iface, addr, pdu);
        },
        os.IPPROTO.UDP => {
            print("UDP packet\n", .{});
            _ = try handleUDP(iface, addr, pdu);
        },
        else => print("other ip protocol with code {d}\n", .{proto}),
    }

    return;
}

pub fn replyIP(iface: *TunDevice, addr: DevAddress, req_pdu: IPv4PDU, buf: *SendBuf) !void {
    const ip_hdr = req_pdu.header;

    var ip_buf = try buf.allocSlot(IpHeaderPtr.size);
    var ip_hdr_reply = IpHeaderPtr.cast(ip_buf);
    ip_hdr_reply.set(.{
        .version = 4,
        .ihl = 5,
        .tos = c.IPTOS_ECN_NOT_ECT,
        .len = @truncate(u16, buf.len),
        .id = ip_hdr.getField(.id),
        .flags = 0b010,
        .frag_offset = 0,
        .ttl = 64,
        .proto = os.IPPROTO.ICMP,
        .header_checksum = 0,
        .sender_addr = addr.ip,
        .dest_addr = ip_hdr.getField(.sender_addr),
    });
    ip_hdr_reply.compute_checksum();

    try replyEthernet(iface, addr, req_pdu.prev, buf);
}

test "Internet Check Sum" {
    const testing = std.testing;

    var buf = [_]u8{ 0x45, 0x00, 0x00, 0x54, 0x41, 0xe0, 0x40, 0x00, 0x40, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x04, 0x0a, 0x00, 0x00, 0x05 };
    var ip_hdr = IpHeaderPtr.cast(&buf);
    ip_hdr.compute_checksum();

    const expected = [_]u8{ 0x45, 0x00, 0x00, 0x54, 0x41, 0xe0, 0x40, 0x00, 0x40, 0x01, 0xe4, 0xc0, 0x0a, 0x00, 0x00, 0x04, 0x0a, 0x00, 0x00, 0x05 };

    try testing.expectEqualSlices(u8, &expected, &buf);
}
