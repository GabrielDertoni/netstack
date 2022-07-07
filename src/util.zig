const c = @cImport({
    @cInclude("arpa/inet.h");
});

const std = @import("std");
const mem = std.mem;
const io = std.io;
const native_endian = @import("builtin").target.cpu.arch.endian();

pub const DevAddress = struct {
    ip: u32,
    mac: u48,
};

pub const SliceWriterError = error{
    SliceFull,
};

pub fn writeToSlice(self: *[]u8, buf: []const u8) SliceWriterError!usize {
    if (self.*.len == 0) return SliceWriterError.SliceFull;
    var count = @minimum(self.*.len, buf.len);
    @memcpy(self.*.ptr, buf.ptr, count);
    self.* = self.*[count..];
    return count;
}

pub const SliceWriter = io.Writer(*[]u8, SliceWriterError, writeToSlice);

pub fn sliceWriter(slice: *[]u8) SliceWriter {
    return SliceWriter{ .context = slice };
}

pub fn internetChecksum(bytes: []const u8) u16 {
    // source: https://datatracker.ietf.org/doc/html/rfc1071

    var count: usize = bytes.len;
    var slice: []const u8 = bytes;
    var sum: u32 = 0;

    while (count > 1) {
        sum += mem.readIntBig(u16, slice[0..2]);
        slice = slice[2..];
        count -= 2;
    }

    if (count > 0) sum += slice[0];
    while ((sum >> 16) != 0) sum = (sum & 0xffff) + (sum >> 16);

    return @truncate(u16, ~sum);
}

pub const IpParseError = error{
    InvalidAddress,
    NotSupported,
};

pub fn parseIp(ip: [*:0]const u8) IpParseError!u32 {
    var addr: u32 = undefined;
    const ret = c.inet_pton(c.AF_INET, ip, @ptrCast(?*anyopaque, &addr));
    if (ret == 0) return IpParseError.InvalidAddress;
    if (ret < 0) return IpParseError.NotSupported;
    return switch (native_endian) {
        .Big => addr,
        .Little => @byteSwap(u32, addr),
    };
}

pub fn parseMac(str: []const u8) std.fmt.ParseIntError!u48 {
    const parseUnsigned = std.fmt.parseUnsigned;
    var result: [6]u8 = undefined;
    var i: usize = 0;
    var slice = str;
    while (i < 6) {
        defer i += 1;
        result[i] = try parseUnsigned(u8, slice[0..2], 16);
        // Skip the ':' character as well.
        if (slice.len >= 3) slice = slice[3..];
    }
    return mem.readIntBig(u48, &result);
}

pub fn macAddrToStr(mac: u48) [18:0]u8 {
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
