const std = @import("std");
const mem = std.mem;
const builtin = @import("builtin");
const native_endian = builtin.target.cpu.arch.endian();
const assert = std.debug.assert;

const util = @import("./util.zig");
const sliceWriter = util.sliceWriter;
const networkToHost = util.networkToHost;
const hostToNetwork = util.hostToNetwork;

pub const EthernetHeaderPtr = struct {
    data: *[Size]u8,

    // destination MAC address - 6 bytes
    // source MAC address      - 6 bytes
    // ethernet type           - 2 bytes
    //                           -------
    //                           14 bytes
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

pub fn mac_addr_to_str(mac: u48) [18:0]u8 {
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
