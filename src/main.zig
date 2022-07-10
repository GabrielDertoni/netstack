//
// God dammit get packed structs working! I had to change the whole way I was doing stuff to a
// worse way simply because I couldn't get the compiler to work with packed structs without crasing
// all the time!
//

const c = @cImport({
    @cInclude("unistd.h");
    @cInclude("netinet/ether.h");
    @cInclude("netinet/ip_icmp.h");
});

pub const io_mode = .evented;

pub var loop_loc: event.Loop = undefined;
pub const event_loop: *event.Loop = &loop_loc;

const std = @import("std");
const mem = std.mem;
const os = std.os;
const event = std.event;

const builtin = @import("builtin");
const native_endian = builtin.target.cpu.arch.endian();
const print = std.debug.print;
const assert = std.debug.assert;

const ethernet = @import("./ethernet.zig");
const arp = @import("./arp.zig");

const TunDevice = @import("./tuntap.zig").TunDevice;

const util = @import("./util.zig");
const DevAddress = util.DevAddress;

pub fn failiableHandleLoop(iface: *TunDevice, addr: DevAddress, wg: *event.WaitGroup, shutdown: os.fd_t) !void {
    defer wg.finish(1);

    const epollfd = try os.epoll_create1(os.linux.EPOLL.CLOEXEC);

    var shutdown_ev = os.linux.epoll_event{
        .events = os.linux.EPOLL.IN,
        .data = os.linux.epoll_data{ .fd = shutdown },
    };
    try os.epoll_ctl(epollfd, os.linux.EPOLL.CTL_ADD, shutdown, &shutdown_ev);

    var iface_ev = os.linux.epoll_event{
        .events = os.linux.EPOLL.IN,
        .data = os.linux.epoll_data{ .fd = iface.fd },
    };
    try os.epoll_ctl(epollfd, os.linux.EPOLL.CTL_ADD, iface.fd, &iface_ev);

    while (true) {
        event.Loop.instance.?.waitUntilFdReadable(epollfd);

        var ev: [1]os.linux.epoll_event = undefined;
        const nevents = os.epoll_wait(epollfd, &ev, -1);
        if (nevents == 0) continue;

        if (ev[0].data.fd == shutdown) break;

        var buf: [1024]u8 = undefined;
        var nbytes = try iface.read(&buf);
        // This should be non blocking and shouldn't suspend. This way we can ensure that we will
        // see the shutdown signal pretty quickly.
        nosuspend try ethernet.handleEthernet(iface, addr, buf[0..nbytes]);
    }
    print("handleLoop is done\n", .{});
}

pub fn handleLoop(iface: *TunDevice, addr: DevAddress, wg: *event.WaitGroup, shutdown: os.fd_t) void {
    failiableHandleLoop(iface, addr, wg, shutdown) catch |err| {
        print("{e}\n", .{err});
    };
}

pub fn main() !u8 {
    // Initialize with a thread poll with only a single thread. We cant use the build single
    // threaded flag because we still want the fs and timer threads to run as OS threads. However,
    // there is only a single worker thread which allows us to do stuff without worrying much about
    // synchronization.
    try event_loop.initThreadPool(1);
    defer event_loop.deinit();

    print("Setup...\n", .{});

    // Do some setup and non async things before we enter async code.
    var iface = try TunDevice.init("tun0");
    defer iface.deinit();

    // Setup the interface
    try util.runCmdSync("sudo ip link set up dev tun0");

    // Add an entry in the route table, making all the network traffic for network 10.0.0 go to the
    // tun0 interface.
    try util.runCmdSync("sudo ip route add to 10.0.0.0/24 dev tun0");

    // Give the interface an IP addres.
    try util.runCmdSync("sudo ip address add 10.0.0.1/24 dev tun0");

    var result: u8 = undefined;
    var frame: @Frame(callAsyncMain) = undefined;
    _ = @asyncCall(&frame, &result, callAsyncMain, .{&iface});
    event_loop.run();

    return result;
}

fn callAsyncMain(iface: *TunDevice) callconv(.Async) u8 {
    event_loop.beginOneEvent();
    defer event_loop.finishOneEvent();

    asyncMain(iface) catch |err| {
        std.log.err("{s}", .{@errorName(err)});
        if (@errorReturnTrace()) |trace| {
            std.debug.dumpStackTrace(trace.*);
        }
        return 1;
    };

    return 0;
}

fn asyncMain(iface: *TunDevice) !void {
    print("Running...\n", .{});

    const ip_str = os.getenv("IP") orelse "10.0.0.2";
    const mac_str = os.getenv("MAC") orelse "00:0c:29:6d:50:25";

    const addr = DevAddress{
        .ip = try util.parseIp(ip_str),
        .mac = try util.parseMac(mac_str),
    };

    const shutdown_fd = try os.eventfd(0, os.linux.EFD.CLOEXEC);

    var the_loop = std.event.Loop.instance.?;

    var wg = std.event.WaitGroup{};
    try wg.begin(1);
    try the_loop.runDetached(std.heap.c_allocator, handleLoop, .{ iface, addr, &wg, shutdown_fd });
    defer {
        const shutdown_bytes = [_]u8{0x1} ** 8;

        print("Shutting down...\n", .{});
        // If we failed to write the shutdown signal, there is no hope that this `wait` will ever
        // complete, just return and the we will shutdown the event loop manually. In that case,
        // exit forcebly.
        _ = os.write(shutdown_fd, &shutdown_bytes) catch {
            print("Failed to send shutdown signal", .{});
            os.exit(1);
        };
        wg.wait();
    }

    std.time.sleep(5 * std.time.ns_per_s);

    var mac = try arp.requestARPIP(iface, addr, try util.parseIp("10.0.0.1"));

    print("got mac: {s}\n", .{util.macAddrToStr(mac)});
    print("Done\n", .{});
}
