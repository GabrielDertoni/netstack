const c = @cImport({
    @cInclude("netinet/if_ether.h");
});

const std = @import("std");
const os = std.os;
const event = std.event;
const mem = std.mem;
const assert = std.debug.assert;
const print = std.debug.print;

const ethernet = @import("./ethernet.zig");
const EthernetPDU = ethernet.EthernetPDU;
const EthernetHeaderPtr = ethernet.EthernetHeaderPtr;
const EthernetProtocol = ethernet.EthernetProtocol;
const replyEthernet = ethernet.replyEthernet;
const sendEthernet = ethernet.sendEthernet;

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

pub fn handleARP(iface: *TunDevice, addr: DevAddress, prev: EthernetPDU) !void {
    const data = prev.sdu;
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
    if (addr.ip != dest_ip) return;

    switch (prev.header.opcode()) {
        c.ARPOP_REQUEST => {
            // Store the sender's MAC into the table since we know it's IP and everything.
            arpInsert(arp_ipv4.sender_ip(), arp_ipv4.sender_mac());

            // Respond.
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
        c.ARPOP_REPLY => {
            print("Storing mac address for arp reply\n", .{});

            // Got a reply, insert into the table
            arpInsert(arp_ipv4.sender_ip(), arp_ipv4.sender_mac());

            const entry = arp_requests.getEntryFor(.{ .req_ip = arp_ipv4.sender_ip() });

            if (entry.node) |node| {
                var bytes: [8]u8 = undefined;
                mem.writeIntNative(u64, &bytes, 1);
                // TODO: Should this really be a try???
                _ = try os.write(node.key.eventfd, &bytes);
            }
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
        .protype = req_pdu.header.protype(),
        .hardware_addr_size = req_pdu.header.hardware_addr_size(),
        .prosize = req_pdu.header.prosize(),
        .opcode = c.ARPOP_REPLY,
    });

    return replyEthernet(iface, addr, req_pdu.prev, buf);
}

const RequestEntry = struct {
    req_ip: u32,

    // Defaults to -1 so that if something wrong happens, we will get invalid fd error.
    eventfd: os.fd_t = -1,

    // This allows for many nodes to be waiting on the same ip using the exact same eventfd. Only
    // the root node is actually inserted in the `RequestQueue`.

    // For some odd reason, using `RequestQueue.Node` won't work here because of a dependency loop.
    // So this pointer is actually pointing to the `key` field inside a `RequestQueue.Node`.
    prev: ?*RequestEntry = null,
    next: ?*RequestEntry = null,
};

fn compareRequestEntry(a: RequestEntry, b: RequestEntry) std.math.Order {
    return std.math.order(a.req_ip, b.req_ip);
}

const RequestQueue = std.Treap(RequestEntry, compareRequestEntry);

// All arp requests that are waiting responses
var arp_requests = RequestQueue{};

pub fn requestARPIP(iface: *TunDevice, addr: DevAddress, ip: u32, timeout_ns: ?u64) !u48 {
    if (arpTryLookup(ip)) |mac| return mac;

    print("Fetching MAC with ARP\n", .{});

    var local_node: RequestQueue.Node = undefined;

    var entry = arp_requests.getEntryFor(.{ .req_ip = ip });
    var eventfd: os.fd_t = undefined;

    if (entry.node) |node| {
        // There is already a request for this ip, join the wait.
        eventfd = node.key.eventfd;
        local_node.key = RequestEntry{ .req_ip = ip, .eventfd = eventfd, .prev = &node.key };
        node.key.next = &local_node.key;
    } else {
        // Send the ARP request
        try sendARPIPRequest(iface, addr, ip);

        // Start waiting for the request
        eventfd = try os.eventfd(0, os.linux.EFD.CLOEXEC);
        entry.key.eventfd = eventfd;

        // `node` is undefined here, but the `set` function will set it up. This parameter is
        // really just providing a memory location to store the node.
        entry.set(&local_node);
    }

    defer {
        if (local_node.key.next) |next| next.prev = local_node.key.prev;
        if (local_node.key.prev) |prev| {
            prev.next = local_node.key.next;
        } else if (local_node.key.next) |next| {
            // This was the root node, the new root node will be the next one.
            var new_entry = arp_requests.getEntryForExisting(&local_node);
            // The key will change, but the `ip` value, which is used for the comparison, won't
            // change. This means that the ordering for the treap won't be invalidated, so it's ok.
            new_entry.key = next.*;
            new_entry.set(@fieldParentPtr(RequestQueue.Node, "key", next));
        } else {
            var new_entry = arp_requests.getEntryForExisting(&local_node);
            // Remove the entry.
            new_entry.set(null);
        }

        if (local_node.key.next == null and local_node.key.prev == null) {
            os.close(entry.key.eventfd);
        }
    }

    if (timeout_ns) |timeout| {
        try util.waitFdTimeout(eventfd, os.linux.EPOLL.IN, timeout);
    } else {
        event.Loop.instance.?.waitUntilFdReadable(eventfd);
    }
    return arpTryLookup(ip) orelse return error.Timeout;
}

pub fn sendARPIPRequest(iface: *TunDevice, addr: DevAddress, ip: u32) !void {
    const pkt_size = EthernetHeaderPtr.Size + ArpHeaderPtr.header_size + ArpIpv4Ptr.data_size;
    // We know in advance that what the maximum size of the packet is
    // going to be. If for some reason, however, it happens
    var buf = std.heap.stackFallback(pkt_size, std.heap.c_allocator);
    var send_buf = SendBuf.init(buf.get());

    // Write arp IPv4 data
    {
        var slot = try send_buf.allocSlot(ArpIpv4Ptr.data_size);
        ArpIpv4Ptr.cast(slot).set(.{
            .sender_mac = addr.mac,
            .sender_ip = addr.ip,
            .destination_mac = 0xffffffffffff, // Broadcast
            .destination_ip = ip,
        });
    }

    // Write arp header
    {
        var slot = try send_buf.allocSlot(ArpHeaderPtr.header_size);
        ArpHeaderPtr.cast(slot).set(.{
            .hardware_type = c.ARPHRD_ETHER,
            .protype = c.ETH_P_IP,
            .hardware_addr_size = 6,
            .prosize = 4,
            .opcode = c.ARPOP_REQUEST,
        });
    }

    return sendEthernet(
        iface,
        addr,
        &send_buf,
        .{ .dest_mac = 0xffffffffffff, .ethertype = EthernetProtocol.Arp },
    );
}

// This is measured in bytes, not ideal, but should work
const ARP_TABLE_MAX_ALLOC = 4096;

var arp_table_buf = [_]u8{0} ** ARP_TABLE_MAX_ALLOC;
var arp_table_alloc = std.heap.FixedBufferAllocator.init(&arp_table_buf);

// The key is the IP address, the value is the MAC address
var arp_table = std.AutoArrayHashMap(u32, u48).init(arp_table_alloc.allocator());

fn arpInsert(ip: u32, mac: u48) void {
    arp_table.put(ip, mac) catch {
        _ = arp_table.pop();
        // This should definetly work, unless we got a bug.
        arp_table.put(ip, mac) catch unreachable;
    };
}

pub fn arpTryLookup(ip: u32) ?u48 {
    return arp_table.get(ip);
}
