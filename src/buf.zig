const std = @import("std");
const mem = std.mem;

pub const SendBuf = struct {
    allocd: ?[]u8 = null,
    len: usize = 0,
    allocator: mem.Allocator,

    const Self = @This();
    var TheEmptySlice = [_]u8{};

    pub fn init(alloc: mem.Allocator) Self {
        return Self{ .allocator = alloc };
    }

    pub fn deinit(self: Self) void {
        if (self.allocd) |allocd| {
            self.allocator.free(allocd);
        }
    }

    pub fn allocSlot(self: *Self, size: usize) mem.Allocator.Error![]u8 {
        try self.reserve(size);
        const allocd = self.allocd.?;
        const end = allocd.len - self.len;
        self.len += size;
        return allocd[end - size .. end];
    }

    pub fn slice(self: *Self) []u8 {
        if (self.allocd) |allocd| {
            return allocd[allocd.len - self.len ..];
        } else {
            return &TheEmptySlice;
        }
    }

    // Ensures that there are at least more `size` bytes as spare capacity.
    pub fn reserve(self: *Self, size: usize) mem.Allocator.Error!void {
        if (self.allocd) |allocd| {
            if (size + self.len > allocd.len) {
                const cap = self.allocd.?.len;
                var new_allocd = try self.allocator.reallocAtLeast(allocd, size + self.len);
                self.allocd = new_allocd;
                mem.copyBackwards(u8, new_allocd[new_allocd.len - self.len ..], new_allocd[cap - self.len .. cap]);
            }
        } else {
            self.allocd = try self.allocator.allocAdvanced(u8, null, size, .at_least);
        }
    }
};
