const c = @cImport({
    @cInclude("linux/if_ether.h");
    @cInclude("linux/if_arp.h");
});

const std = @import("std");
const mem = std.mem;
const assert = std.debug.assert;
const print = std.debug.print;

const EthernetHeaderPtr = @import("./ethernet.zig").EthernetHeaderPtr;
const TunDevice = @import("./tuntap.zig").TunDevice;

pub const ArpHeaderPtr = struct {
    data: *[Size]u8,

    // hardware_type      - 2 bytes
    // protype            - 2 bytes
    // hardware_addr_size - 1 byte
    // prosize            - 1 byte
    // opcode             - 2 bytes
    //                      -------
    //                      8 bytes
    pub const Size = 8;
    const Self = @This();

    pub fn cast(buf: []u8) Self {
        assert(buf.len >= Size);
        return Self{ .data = buf[0..Size] };
    }

    pub fn hardware_type(self: Self) u16 {
        return mem.readIntBig(u16, self.data[0..2]);
    }

    pub fn set_hardware_type(self: Self, val: u16) void {
        mem.writeIntBig(u16, self.data[0..2], val);
    }

    pub fn protype(self: Self) u16 {
        return mem.readIntBig(u16, self.data[2..4]);
    }

    pub fn set_protype(self: Self, val: u16) void {
        mem.writeIntBig(u16, self.data[2..4], val);
    }

    pub fn hardware_addr_size(self: Self) u8 {
        return self.data[4];
    }

    pub fn set_hardware_addr_size(self: Self, val: u8) void {
        self.data[4] = val;
    }

    pub fn prosize(self: Self) u8 {
        return self.data[5];
    }

    pub fn set_prosize(self: Self, val: u8) void {
        self.data[5] = val;
    }

    pub fn opcode(self: Self) u16 {
        return mem.readIntBig(u16, self.data[6..8]);
    }

    pub fn set_opcode(self: Self, val: u16) void {
        mem.writeIntBig(u16, self.data[6..8], val);
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
            if (comptime mem.eql(u8, field.name, "hardware_type")) {
                self.set_hardware_type(val.hardware_type);
            } else if (comptime mem.eql(u8, field.name, "protype")) {
                self.set_protype(val.protype);
            } else if (comptime mem.eql(u8, field.name, "hardware_addr_size")) {
                self.set_hardware_addr_size(val.hardware_addr_size);
            } else if (comptime mem.eql(u8, field.name, "prosize")) {
                self.set_prosize(val.prosize);
            } else if (comptime mem.eql(u8, field.name, "opcode")) {
                self.set_opcode(val.opcode);
            } else {
                @compileError("unexpected field " ++ field.name);
            }
        }
    }
};

const ArpIpv4Ptr = packed struct {
    data: *[Size]u8,

    // sender_mac      - 6 bytes
    // sender_ip       - 4 bytes
    // destination_mac - 6 bytes
    // destination_ip  - 4 bytes
    //                   -------
    //                   20 bytes
    const Size = 20;
    const Self = @This();

    pub fn cast(buf: []u8) Self {
        assert(buf.len >= Size);
        return Self{ .data = buf[0..Size] };
    }

    pub fn sender_mac(self: Self) u48 {
        return mem.readIntBig(u48, self.data[0..6]);
    }

    pub fn set_sender_mac(self: Self, val: u48) void {
        mem.writeIntBig(u48, self.data[0..6], val);
    }

    pub fn sender_ip(self: Self) u32 {
        return mem.readIntBig(u32, self.data[6..10]);
    }

    pub fn set_sender_ip(self: Self, val: u32) void {
        mem.writeIntBig(u32, self.data[6..10], val);
    }

    pub fn destination_mac(self: Self) u48 {
        return mem.readIntBig(u48, self.data[10..16]);
    }

    pub fn set_destination_mac(self: Self, val: u48) void {
        mem.writeIntBig(u48, self.data[10..16], val);
    }

    pub fn destination_ip(self: Self) u32 {
        return mem.readIntBig(u32, self.data[16..20]);
    }

    pub fn set_destination_ip(self: Self, val: u32) void {
        mem.writeIntBig(u32, self.data[16..20], val);
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
            if (comptime mem.eql(u8, field.name, "sender_mac")) {
                self.set_sender_mac(val.sender_mac);
            } else if (comptime mem.eql(u8, field.name, "sender_ip")) {
                self.set_sender_ip(val.sender_ip);
            } else if (comptime mem.eql(u8, field.name, "destination_mac")) {
                self.set_destination_mac(val.destination_mac);
            } else if (comptime mem.eql(u8, field.name, "destination_ip")) {
                self.set_destination_ip(val.destination_ip);
            } else {
                @compileError("unexpected field " ++ field.name);
            }
        }
    }
};

// const ArpError = error{
//     UnexpectedHardware,
//     UnexpectedProtocol,
//     FrameNotForUs,
// };

pub fn handle_arp(iface: *TunDevice, ip: u32, mac: u48, data: []u8) !void {
    print("handling arp\n", .{});
    var arp_hdr = ArpHeaderPtr.cast(data);

    if (arp_hdr.hardware_type() != c.ARPHRD_ETHER) {
        print("Unexpected hardware\n", .{});
        return error.UnexpectedHardware;
    }

    if (arp_hdr.protype() != c.ETH_P_IP) {
        print("UnexpectedProtocol\n", .{});
        return error.UnexpectedProtocol;
    }

    var arp_ipv4 = ArpIpv4Ptr.cast(data[ArpHeaderPtr.Size..]);

    const dest_ip = arp_ipv4.destination_ip();
    // TODO: Update translation table
    if (ip != dest_ip) return error.FrameNotForUs;

    switch (arp_hdr.opcode()) {
        c.ARPOP_REQUEST => {
            const pkt_size = EthernetHeaderPtr.Size + ArpHeaderPtr.Size + ArpIpv4Ptr.Size;
            var buf = [_]u8{0} ** pkt_size;

            var rest: []u8 = &buf;
            EthernetHeaderPtr.cast(rest).set(.{
                .dest_mac = arp_ipv4.sender_mac(),
                .src_mac = mac,
                .ethertype = c.ETH_P_ARP,
            });
            rest = rest[EthernetHeaderPtr.Size..];
            ArpHeaderPtr.cast(rest).set(.{
                .hardware_type = c.ARPHRD_ETHER,
                .protype = c.ETH_P_IP,
                .hardware_addr_size = 6,
                .prosize = 4,
                .opcode = c.ARPOP_REPLY,
            });
            rest = rest[ArpHeaderPtr.Size..];
            ArpIpv4Ptr.cast(rest).set(.{
                .sender_mac = mac,
                .sender_ip = ip,
                .destination_mac = arp_ipv4.sender_mac(),
                .destination_ip = arp_ipv4.sender_ip(),
            });

            try iface.writer().writeAll(&buf);
        },
        else => {
            print("Not an arp request\n", .{});
            return;
        },
    }
}
