const std = @import("std");
const assert = std.debug.assert;

const MakePackedStructPtr = @import("./packed_struct_ptr.zig").MakePackedStructPtr;

const TunDevice = @import("./tuntap.zig").TunDevice;

const util = @import("./util.zig");
const DevAddress = util.DevAddress;
const internetChecksum = util.internetChecksum;

const ip = @import("./ip.zig");
const IPv4PDU = ip.IPv4PDU;

const UDPHeaderPtr = struct {
    data: *Inner.Data,

    const Inner = MakePackedStructPtr(.{
        .src_port = u16,
        .dest_port = u16,
        .len = u16,
        .checksum = u16,
    });
    const Self = @This();

    pub fn cast(buf: []u8) Self {
        assert(buf.len >= Inner.size);
        return Self{ .data = buf[0..Inner.size] };
    }

    pub fn check(self: Self) !void {
        if (internetChecksum(self.data) != 0) return error.ChecksumFailed;
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
};

pub fn handleUDP(iface: *TunDevice, addr: DevAddress, prev: IPv4PDU) !void {
    const udp_hdr = UDPHeaderPtr.cast(prev.sdu);
    _ = udp_hdr;
    _ = iface;
    _ = addr;
    _ = prev;
}
