const c = @cImport({
    @cInclude("netinet/if_ether.h");
});

const std = @import("std");
const mem = std.mem;
const assert = std.debug.assert;
const print = std.debug.print;

const ethernet = @import("./ethernet.zig");
const EthernetPDU = ethernet.EthernetPDU;
const EthernetHeaderPtr = ethernet.EthernetHeaderPtr;
const replyEthernet = ethernet.replyEthernet;

const TunDevice = @import("./tuntap.zig").TunDevice;

const util = @import("./util.zig");
const DevAddress = util.DevAddress;

const SendBuf = @import("./buf.zig").SendBuf;

pub const ArpPDU = struct {
    prev: EthernetPDU,
    header: ArpHeaderPtr,
    sdu: []u8,
};

pub const ArpHeaderPtr = struct {
    data: *[header_size]u8,

    // hardware_type      - 16 bits
    // protype            - 16 bits
    // hardware_addr_size - 8 bits
    // prosize            - 8 bits
    // opcode             - 16 bits
    //                      -------
    //                      64 bits
    //                      8 bytes
    pub const header_size = 8;
    const Self = @This();

    pub fn cast(buf: []u8) Self {
        assert(buf.len >= header_size);
        return Self{ .data = buf[0..header_size] };
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

    pub fn as_bytes(self: Self) *const [header_size]u8 {
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

pub const ArpIpv4Ptr = packed struct {
    data: *[data_size]u8,

    // sender_mac      - 48 bits
    // sender_ip       - 32 bits
    // destination_mac - 48 bits
    // destination_ip  - 32 bits
    //                   -------
    //                   160 bits
    //                   20 bytes
    pub const data_size = 20;
    const Self = @This();

    pub fn cast(buf: []u8) Self {
        assert(buf.len >= data_size);
        return Self{ .data = buf[0..data_size] };
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

    pub fn as_bytes(self: Self) *const [data_size]u8 {
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

pub fn handleARP(iface: *TunDevice, addr: DevAddress, prev: EthernetPDU) !void {
    const data = prev.sdu;
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

    const pdu = ArpPDU{
        .prev = prev,
        .header = arp_hdr,
        .sdu = data[ArpHeaderPtr.header_size..],
    };

    return handleARPIP(iface, addr, pdu);
}

pub fn handleARPIP(iface: *TunDevice, addr: DevAddress, prev: ArpPDU) !void {
    const data = prev.sdu;
    var arp_ipv4 = ArpIpv4Ptr.cast(data);

    const dest_ip = arp_ipv4.destination_ip();
    // TODO: Update translation table
    if (addr.ip != dest_ip) return error.FrameNotForUs;

    switch (prev.header.opcode()) {
        c.ARPOP_REQUEST => {
            const pkt_size = EthernetHeaderPtr.Size + ArpHeaderPtr.header_size + ArpIpv4Ptr.data_size;
            // We know in advance that what the maximum size of the packet is
            // going to be. If for some reason, however, it happens
            var buf = std.heap.stackFallback(pkt_size, std.heap.c_allocator);
            var send_buf = SendBuf.init(buf.get());

            var slot = try send_buf.allocSlot(ArpIpv4Ptr.data_size);
            ArpIpv4Ptr.cast(slot).set(.{
                .sender_mac = addr.mac,
                .sender_ip = addr.ip,
                .destination_mac = arp_ipv4.sender_mac(),
                .destination_ip = arp_ipv4.sender_ip(),
            });

            return replyARP(iface, addr, prev, &send_buf);
        },
        else => {
            print("Not an arp request\n", .{});
            return;
        },
    }
}

pub fn replyARP(iface: *TunDevice, addr: DevAddress, req_pdu: ArpPDU, buf: *SendBuf) !void {
    var slot = try buf.allocSlot(ArpHeaderPtr.header_size);
    ArpHeaderPtr.cast(slot).set(.{
        .hardware_type = c.ARPHRD_ETHER,
        .protype = c.ETH_P_IP,
        .hardware_addr_size = 6,
        .prosize = 4,
        .opcode = c.ARPOP_REPLY,
    });

    return replyEthernet(iface, addr, req_pdu.prev, buf);
}
