const c = @cImport(@cInclude("netinet/ip_icmp.h"));

const std = @import("std");
const os = std.os;
const mem = std.mem;
const print = std.debug.print;
const assert = std.debug.assert;

const arp = @import("./arp.zig");

const ethernet = @import("./ethernet.zig");
const EthernetHeaderPtr = ethernet.EthernetHeaderPtr;

const ip_mod = @import("./ip.zig");
const IPv4PDU = ip_mod.IPv4PDU;
const IpHeaderPtr = ip_mod.IpHeaderPtr;
const TunDevice = @import("./tuntap.zig").TunDevice;

const util = @import("./util.zig");
const DevAddress = util.DevAddress;

const SendBuf = @import("./buf.zig").SendBuf;

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
        return Self{ .data = buf[0..Size], .pkt_len = buf.len };
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

    switch (icmp_hdr.@"type"()) {
        c.ICMP_ECHO => return handleICMPEcho(iface, addr, pdu),
        c.ICMP_ECHOREPLY => {
            const icmp_echo = ICMPv4EchoPtr.cast(icmp_hdr.restOfHeader());
            var entry = pending_requests.getEntryFor(.{
                .ip = prev.header.getField(.sender_addr),
                .id = icmp_echo.id(),
            });

            if (entry.node) |node| {
                node.key.response = pdu;
                notifyWaiters();
            }
        },
        c.ICMP_DEST_UNREACH => {
            // This block contains the handler code. If the code breaks out of it, it will treat as
            // a failure to handle.
            handle_blk: {
                const icmp_dest_unreach = ICMPv4DestUnreachable.cast(icmp_hdr.restOfHeader());
                // TODO: Do something with this. The RFC 792 says that it is unused, but other
                // sources say it has a `len` and `var` fields.
                _ = icmp_dest_unreach;

                var payload = pdu.sdu;
                const ip_hdr = ip_mod.IpHeaderPtr.cast(payload);
                payload = payload[@as(usize, ip_hdr.getField(.ihl)) * 4 ..];

                if (ip_hdr.getField(.proto) != os.IPPROTO.ICMP) break :handle_blk;

                const unreach_icmp_hdr = ICMPv4HeaderPtr.cast(payload);
                switch (unreach_icmp_hdr.@"type"()) {
                    c.ICMP_ECHO => {
                        const unreach_icmp_echo = ICMPv4EchoPtr.cast(unreach_icmp_hdr.restOfHeader());

                        // An echo that we sent was to an unreachable destination
                        var entry = pending_requests.getEntryFor(.{
                            .ip = ip_hdr.getField(.dest_addr),
                            .id = unreach_icmp_echo.id(),
                        });

                        if (entry.node) |node| {
                            node.key.response = pdu;
                            notifyWaiters();
                            return;
                        } else {
                            break :handle_blk;
                        }
                    },
                    else => break :handle_blk,
                }
            }

            print("Unhandled destination unreachable\n", .{});
            return;
        },
        // TODO: add support for `c.ICMP_DEST_UNREACH`.
        else => print("Received an unexpected icmp packed\n", .{}),
    }
}

fn notifyWaiters() void {
    // Notify all waiters
    var bytes: [8]u8 = undefined;
    mem.writeIntNative(u64, &bytes, icmp_waiters);
    _ = os.write(icmp_eventfd, &bytes) catch {};
}

pub fn handleICMPEcho(iface: *TunDevice, addr: DevAddress, prev: ICMPv4PDU) !void {
    const icmp_echo = ICMPv4EchoPtr.cast(prev.header.restOfHeader());

    // The value 64 is just a guess on the size that the `data` segment may have.
    const expected_size = EthernetHeaderPtr.Size + IpHeaderPtr.size + ICMPv4HeaderPtr.Size + 64;

    var alloc = std.heap.stackFallback(expected_size, std.heap.c_allocator);

    var buf = SendBuf.init(alloc.get());
    defer buf.deinit();

    try buf.reserve(EthernetHeaderPtr.Size + IpHeaderPtr.size + ICMPv4HeaderPtr.Size + prev.sdu.len);

    var icmp_data_buf = try buf.allocSlot(prev.sdu.len);
    std.mem.copy(u8, icmp_data_buf, prev.sdu);

    var icmp_buf = try buf.allocSlot(ICMPv4HeaderPtr.Size);
    var icmp_hdr_reply = ICMPv4HeaderPtr.cast(icmp_buf);
    icmp_hdr_reply.set(.{
        .type = c.ICMP_ECHOREPLY,
        .code = 0,
        .checksum = 0,
    });
    std.mem.copy(u8, icmp_hdr_reply.restOfHeader(), icmp_echo.data);
    icmp_hdr_reply.setChecksum(util.internetChecksum(buf.slice()));

    try ip_mod.replyIP(iface, addr, prev.prev, &buf);
}

// This single eventfd will notify all waiting icmp echo requests. This means that when it fires,
// the response was received by **some** of the waiting requests. However, all of them will receive
// the notification. This is a bit of overhead, but it should be ok since it reduces the code
// complexity and the number of required eventfds. Whenever a reply is received, the handler
// (`handleICMP`) will write `icmp_waiters` to `icmp_eventfd` which is in semaphore mode. This
// means that the number of reads that must happen for the eventfd to become blocking again is
// `icmp_waiters`. As a result waiters will be notified and should read from the eventfd to
// decrease its count.
var icmp_eventfd: os.fd_t = -1;
var icmp_waiters: u64 = 0;

const RequestEntry = struct {
    ip: u32,
    id: u16,
    response: ?ICMPv4PDU = null,
};

fn compareRequestEntry(a: RequestEntry, b: RequestEntry) std.math.Order {
    const order1 = std.math.order(a.ip, b.ip);
    if (order1 != .eq) return order1;
    return std.math.order(a.id, b.id);
}

const PendingRequests = std.Treap(RequestEntry, compareRequestEntry);

var pending_requests = PendingRequests{};

pub fn ping(iface: *TunDevice, addr: DevAddress, ip: u32, timeout_ns: ?u64) !void {
    var timer = if (timeout_ns != null) try std.time.Timer.start() else undefined;

    var id: u16 = undefined;
    while (true) {
        id = (nosuspend sendICMPEcho(iface, addr, ip)) catch |err| switch (err) {
            error.NoMac => {
                var gateway_ip: u32 = undefined;

                // TODO: This should not be hard coded.
                const mask = 0xffffff00;
                // If the target ip is not in the same network as us, use the MAC of the default gateway.
                if ((ip & mask) != (addr.ip & mask)) {
                    const default_gateway: u32 = 0x0a000001; // 10.0.0.1
                    gateway_ip = default_gateway;
                } else {
                    gateway_ip = ip;
                }
                _ = try arp.requestARPIP(iface, addr, gateway_ip, timeout_ns);
                continue;
            },
            else => return err,
        };
        break;
    }

    var node: PendingRequests.Node = undefined;
    var entry = pending_requests.getEntryFor(.{ .ip = ip, .id = id });

    entry.set(&node);

    defer {
        // Remove the node from the treap.
        pending_requests.getEntryForExisting(&node).set(null);
    }

    while (true) {
        if (timeout_ns) |timeout| {
            const time = timer.read();
            if (time >= timeout) return error.Timeout;

            icmp_waiters += 1;
            defer icmp_waiters -= 1;

            try util.waitFdTimeout(icmp_eventfd, os.linux.EPOLL.IN, timeout - time);
        } else {
            icmp_waiters += 1;
            defer icmp_waiters -= 1;

            std.event.Loop.instance.?.waitUntilFdReadable(icmp_eventfd);
        }

        // Acknowledge notification
        var bytes: [8]u8 = undefined;
        _ = os.read(icmp_eventfd, &bytes) catch {};

        if (node.key.response) |response| {
            switch (response.header.@"type"()) {
                c.ICMP_ECHOREPLY => return,
                c.ICMP_DEST_UNREACH => return error.DestinationUnreachable,
                else => unreachable,
            }
        }
    }
}

var icmp_pkt_seq: u16 = 1;

pub fn sendICMPEcho(iface: *TunDevice, addr: DevAddress, ip: u32) !u16 {
    const expected_size = EthernetHeaderPtr.Size + IpHeaderPtr.size + ICMPv4HeaderPtr.Size;

    var alloc = std.heap.stackFallback(expected_size, std.heap.c_allocator);
    var buf = SendBuf.init(alloc.get());
    defer buf.deinit();

    try buf.reserve(expected_size);

    var icmp_buf = try buf.allocSlot(ICMPv4HeaderPtr.Size);
    var icmp_hdr = ICMPv4HeaderPtr.cast(icmp_buf);
    icmp_hdr.set(.{
        .type = c.ICMP_ECHO,
        .code = 0,
        .checksum = 0,
    });
    const id = 0x6891;
    ICMPv4EchoPtr.cast(icmp_hdr.restOfHeader()).set(.{
        .id = 0x6891,
        .seq = icmp_pkt_seq,
    });
    icmp_pkt_seq +%= 1;
    icmp_hdr.setChecksum(util.internetChecksum(buf.slice()));

    try ip_mod.sendIP(iface, addr, ip, &buf);
    return id;
}

pub fn icmpInit() !void {
    icmp_eventfd = try os.eventfd(0, os.linux.EFD.CLOEXEC | os.linux.EFD.SEMAPHORE);
}

pub fn icmpDeinit() void {
    os.close(icmp_eventfd);
}
