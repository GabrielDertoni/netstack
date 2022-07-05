const std = @import("std");
const io = std.io;

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

pub fn SepByWriter(comptime W: type) type {
    return struct {
        start: bool,
        sep: []const u8,
        inner: W,

        const Self = @This();
        const Writer = io.Writer(*Self, W.Error, write);

        pub fn init(inner: W, sep: []const u8) Self {
            return Self{
                .start = false,
                .inner = inner,
                .sep = sep,
            };
        }

        pub fn write(self: *Self, buf: []const u8) !usize {
            if (self.*.start) {
                try self.*.inner.writeAll(self.*.sep);
            } else {
                self.*.start = true;
            }

            return self.*.inner.write(buf);
        }

        pub fn writer(self: *Self) Writer {
            return Writer{ .context = self };
        }
    };
}

pub fn sepByWriter(inner: anytype, sep: []const u8) SepByWriter(@TypeOf(inner)) {
    return SepByWriter(@TypeOf(inner)).init(inner, sep);
}
