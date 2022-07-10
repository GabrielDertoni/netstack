const c = @cImport(@cInclude("netinet/ether.h"));

const std = @import("std");
const mem = std.mem;
const builtin = @import("builtin");
const native_endian = builtin.target.cpu.arch.endian();
const assert = std.debug.assert;

const handleARP = @import("./arp.zig").handleARP;
const handleIP = @import("./ip.zig").handleIP;

const TunDevice = @import("./tuntap.zig").TunDevice;

const SendBuf = @import("./buf.zig").SendBuf;

const util = @import("./util.zig");
const DevAddress = util.DevAddress;
const sliceWriter = util.sliceWriter;
const networkToHost = util.networkToHost;
const hostToNetwork = util.hostToNetwork;

pub const EthernetPDU = struct {
    header: EthernetHeaderPtr,
    sdu: []u8,
};

pub const EthernetHeaderPtr = struct {
    data: *[Size]u8,

    // dest_mac  - 48 bits
    // src_mac   - 48 bits
    // ethertype - 16 bits
    //             -------
    //             112 bits
    //             14 bytes
    pub const Size = 14;
    const Self = @This();

    pub fn cast(buf: []u8) Self {
        assert(buf.len >= Size);
        return Self{ .data = buf[0..Size] };
    }

    pub fn dest_mac(self: Self) u48 {
        return mem.readIntBig(u48, self.data[0..6]);
    }

    pub fn set_dest_mac(self: Self, val: u48) void {
        mem.writeIntBig(u48, self.data[0..6], val);
    }

    pub fn src_mac(self: Self) u48 {
        return mem.readIntBig(u48, self.data[6..12]);
    }

    pub fn set_src_mac(self: Self, val: u48) void {
        mem.writeIntBig(u48, self.data[6..12], val);
    }

    pub fn ethertype(self: Self) u16 {
        return mem.readIntBig(u16, self.data[12..14]);
    }

    pub fn set_ethertype(self: Self, val: u16) void {
        mem.writeIntBig(u16, self.data[12..14], val);
    }

    pub fn as_bytes(self: Self) *const [Size]u8 {
        return self.data;
    }

    pub fn set(self: Self, val: anytype) void {
        const T = @TypeOf(val);
        const info = @typeInfo(T);
        const struct_info = switch (info) {
            .Struct => |i| i,
            else => @compileError("val must be a struct"),
        };
        inline for (struct_info.fields) |field| {
            if (comptime mem.eql(u8, field.name, "dest_mac")) {
                self.set_dest_mac(val.dest_mac);
            } else if (comptime mem.eql(u8, field.name, "src_mac")) {
                self.set_src_mac(val.src_mac);
            } else if (comptime mem.eql(u8, field.name, "ethertype")) {
                self.set_ethertype(val.ethertype);
            } else {
                @compileError("unexpected field " ++ field.name);
            }
        }
    }
};

pub const EthernetProtocol = enum(u16) {
    Ip = c.ETH_P_IP,
    Arp = c.ETH_P_ARP,
};

pub fn handleEthernet(iface: *TunDevice, addr: DevAddress, prev: []u8) !void {
    const data = prev;
    var ether_hdr = EthernetHeaderPtr.cast(data);
    const pdu = EthernetPDU{
        .header = ether_hdr,
        .sdu = data[EthernetHeaderPtr.Size..],
    };
    const ethertype = ether_hdr.ethertype();
    if (ethertype != c.ETH_P_ARP and ethertype != c.ETH_P_IP) return;

    switch (ethertype) {
        c.ETH_P_ARP => try handleARP(iface, addr, pdu),
        c.ETH_P_IP => try handleIP(iface, addr, pdu),
        else => {},
    }
}

pub fn replyEthernet(
    iface: *TunDevice,
    addr: DevAddress,
    req_pdu: EthernetPDU,
    buf: *SendBuf,
) !void {
    const ether_hdr = req_pdu.header;
    return sendEthernet(
        iface,
        addr,
        buf,
        .{
            .dest_mac = ether_hdr.src_mac(),
            .ethertype = req_pdu.header.ethertype(),
        },
    );
}

pub fn sendEthernet(
    iface: *TunDevice,
    addr: DevAddress,
    buf: *SendBuf,
    params: anytype,
) !void {
    comptime assert(blk: {
        const T = @TypeOf(params);
        break :blk @hasField(T, "dest_mac") and @hasField(T, "ethertype");
    });
    comptime assert(blk: {
        const T = @TypeOf(params.ethertype);
        break :blk T == EthernetProtocol or T == u16;
    });

    var ether_buf = try buf.allocSlot(EthernetHeaderPtr.Size);
    EthernetHeaderPtr.cast(ether_buf).set(.{
        .dest_mac = params.dest_mac,
        .src_mac = addr.mac,
        .ethertype = switch (@TypeOf(params.ethertype)) {
            u16 => params.ethertype,
            EthernetProtocol => @enumToInt(params.ethertype),
            else => unreachable,
        },
    });

    try iface.writer().writeAll(buf.slice());
}
