const std = @import("std");
const mem = std.mem;
const assert = std.debug.assert;
const builtin = std.builtin;
const Type = builtin.Type;

const native_endian = @import("builtin").target.cpu.arch.endian();

pub fn MakePackedStructPtr(template: anytype) type {
    const info = @typeInfo(@TypeOf(template));
    if (info != .Struct) @compileError("template has to be a struct");
    const template_info = info.Struct;

    var gen_field: [std.math.maxInt(u8)]Type.EnumField = undefined;

    var mut_bit_size = 0;
    var enum_value = 0;
    inline for (template_info.fields) |field, i| {
        const FieldType = @field(template, field.name);
        const f_info = @typeInfo(FieldType);
        if (@TypeOf(FieldType) != type or f_info != .Int or f_info.Int.signedness != .unsigned) {
            @compileError("the fields of the tamplate must be unsigned int types");
        }

        gen_field[i] = Type.EnumField{
            .name = field.name,
            .value = enum_value,
        };

        mut_bit_size += @bitSizeOf(FieldType);
        enum_value += 1;
    }

    const field_enum = Type.Enum{
        .layout = Type.ContainerLayout.Auto,
        .tag_type = u8,
        .fields = gen_field[0..template_info.fields.len],
        .decls = &.{},
        .is_exhaustive = true,
    };

    const bit_size = mut_bit_size;
    if (bit_size % 8 != 0) @compileError("sum of bit sizes must be divisible by 8");
    return struct {
        pub const Data = [size]u8;

        pub const bit_size = bit_size;
        pub const size = @divExact(bit_size, 8);
        pub const Field = @Type(Type{ .Enum = field_enum });

        pub fn fieldBitOffset(comptime field: Field) usize {
            var offset: usize = 0;

            inline for (template_info.fields) |f| {
                if (comptime mem.eql(u8, f.name, @tagName(field))) return offset;
                offset += @typeInfo(@field(template, f.name)).Int.bits;
            }
            unreachable;
        }

        pub fn FieldTypeOf(comptime field: Field) type {
            const name = @tagName(field);
            inline for (template_info.fields) |f| {
                if (comptime mem.eql(u8, f.name, name)) {
                    return @field(template, f.name);
                }
            }
            unreachable;
        }

        pub fn setField(
            comptime field: Field,
            data: *Data,
            value: FieldTypeOf(field),
        ) void {
            const FieldType = FieldTypeOf(field);
            // const Helper = std.packed_int_array.PackedIntIo(FieldType, .Big);
            const Helper = PackedIntIo(FieldType, .Big);
            Helper.setBits(data[0..], fieldBitOffset(field), value);
        }

        pub fn getField(comptime field: Field, data: *Data) FieldTypeOf(field) {
            const FieldType = FieldTypeOf(field);
            // const Helper = std.packed_int_array.PackedIntIo(FieldType, .Big);
            const Helper = PackedIntIo(FieldType, .Big);
            return Helper.getBits(data[0..], fieldBitOffset(field));
        }

        pub fn set(input: anytype, data: *Data) void {
            const input_info = @typeInfo(@TypeOf(input));
            if (input_info != .Struct) @compileError("input must be a struct");

            inline for (input_info.Struct.fields) |field| {
                setField(@field(Field, field.name), data, @field(input, field.name));
            }
        }
    };
}

pub fn PackedIntIo(comptime Int: type, comptime endian: builtin.Endian) type {
    // The general technique employed here is to cast bytes in the array to a container
    // integer (having bits % 8 == 0) large enough to contain the number of bits we want,
    // then we can retrieve or store the new value with a relative minimum of masking
    // and shifting. In this worst case, this means that we'll need an integer that's
    // actually 1 byte larger than the minimum required to store the bits, because it
    // is possible that the bits start at the end of the first byte, continue through
    // zero or more, then end in the beginning of the last. But, if we try to access
    // a value in the very last byte of memory with that integer size, that extra byte
    // will be out of bounds. Depending on the circumstances of the memory, that might
    // mean the OS fatally kills the program. Thus, we use a larger container (MaxIo)
    // most of the time, but a smaller container (MinIo) when touching the last byte
    // of the memory.
    const int_bits = @bitSizeOf(Int);

    // We bitcast the desired Int type to an unsigned version of itself
    // to avoid issues with shifting signed ints.
    const UnInt = std.meta.Int(.unsigned, int_bits);

    // In the best case, this is the number of bytes we need to touch
    // to read or write a value, as bits.
    const min_io_bits = ((int_bits + 7) / 8) * 8;

    // The maximum container int type
    const Container = std.meta.Int(.unsigned, min_io_bits);

    return struct {
        pub fn getBits(bytes: []const u8, bit_index: usize) Int {
            const container_bits = @bitSizeOf(Container);
            const Shift = std.math.Log2Int(Container);

            const start_byte = bit_index / 8;
            const head_keep_bits = bit_index - (start_byte * 8);
            const tail_keep_bits = container_bits - (int_bits + head_keep_bits);

            //read bytes as container
            const value_ptr = @ptrCast(*align(1) const Container, &bytes[start_byte]);
            var value = value_ptr.*;

            if (endian != native_endian) value = @byteSwap(Container, value);

            switch (endian) {
                .Big => {
                    value <<= @intCast(Shift, head_keep_bits);
                    value >>= @intCast(Shift, head_keep_bits);
                    value >>= @intCast(Shift, tail_keep_bits);
                },
                .Little => {
                    value <<= @intCast(Shift, tail_keep_bits);
                    value >>= @intCast(Shift, tail_keep_bits);
                    value >>= @intCast(Shift, head_keep_bits);
                },
            }

            return @bitCast(Int, @truncate(UnInt, value));
        }

        pub fn setBits(bytes: []u8, bit_index: usize, int: Int) void {
            const container_bits = @bitSizeOf(Container);
            const Shift = std.math.Log2Int(Container);

            const start_byte = bit_index / 8;
            const head_keep_bits = bit_index - (start_byte * 8);
            const tail_keep_bits = container_bits - (int_bits + head_keep_bits);

            const keep_shift = switch (endian) {
                .Big => @intCast(Shift, tail_keep_bits),
                .Little => @intCast(Shift, head_keep_bits),
            };

            //position the bits where they need to be in the container
            const value = @intCast(Container, @bitCast(UnInt, int)) << keep_shift;

            //read existing bytes
            const target_ptr = @ptrCast(*align(1) Container, &bytes[start_byte]);
            var target = target_ptr.*;

            if (endian != native_endian) target = @byteSwap(Container, target);

            //zero the bits we want to replace in the existing bytes
            const inv_mask = @intCast(Container, std.math.maxInt(UnInt)) << keep_shift;
            const mask = ~inv_mask;
            target &= mask;

            //merge the new value
            target |= value;

            if (endian != native_endian) target = @byteSwap(Container, target);

            //save it back
            target_ptr.* = target;
        }
    };
}
