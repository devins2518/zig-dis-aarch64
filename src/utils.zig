const std = @import("std");

pub const Register = enum {
    const Self = @This();

    // zig fmt: off
    w0,  w1,  w2,  w3,  w4,  w5,  w6,  w7,  w8,  w9,  w10, w11, w12, w13, w14, w15,
    w16, w17, w18, w19, w20, w21, w22, w23, w24, w25, w26, w27, w28, w29, w30, wzr,

    x0,  x1,  x2,  x3,  x4,  x5,  x6,  x7,  x8,  x9,  x10, x11, x12, x13, x14, x15,
    x16, x17, x18, x19, x20, x21, x22, x23, x24, x25, x26, x27, x28, x29, x30, xzr,

    wsp, sp,
    // zig fmt: on

    pub fn from(enc: u5, width: Width, sp: bool) Self {
        const x = width == .x;
        return switch (enc) {
            0 => if (x) Self.x0 else Self.w0,
            1 => if (x) Self.x1 else Self.w1,
            2 => if (x) Self.x2 else Self.w2,
            3 => if (x) Self.x3 else Self.w3,
            4 => if (x) Self.x4 else Self.w4,
            5 => if (x) Self.x5 else Self.w5,
            6 => if (x) Self.x6 else Self.w6,
            7 => if (x) Self.x7 else Self.w7,
            8 => if (x) Self.x8 else Self.w8,
            9 => if (x) Self.x9 else Self.w9,
            10 => if (x) Self.x10 else Self.w10,
            11 => if (x) Self.x11 else Self.w11,
            12 => if (x) Self.x12 else Self.w12,
            13 => if (x) Self.x13 else Self.w13,
            14 => if (x) Self.x14 else Self.w14,
            15 => if (x) Self.x15 else Self.w15,
            16 => if (x) Self.x16 else Self.w16,
            17 => if (x) Self.x17 else Self.w17,
            18 => if (x) Self.x18 else Self.w18,
            19 => if (x) Self.x19 else Self.w19,
            20 => if (x) Self.x20 else Self.w20,
            21 => if (x) Self.x21 else Self.w21,
            22 => if (x) Self.x22 else Self.w22,
            23 => if (x) Self.x23 else Self.w23,
            24 => if (x) Self.x24 else Self.w24,
            25 => if (x) Self.x25 else Self.w25,
            26 => if (x) Self.x26 else Self.w26,
            27 => if (x) Self.x27 else Self.w27,
            28 => if (x) Self.x28 else Self.w28,
            29 => if (x) Self.x29 else Self.w29,
            30 => if (x) Self.x30 else Self.w30,
            31 => if (x) if (sp) Self.sp else Self.xzr else if (sp) Self.wsp else Self.wzr,
        };
    }

    pub fn format(value: *const Self, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        try writer.writeAll(@tagName(value.*));
    }
};

pub const Width = enum {
    const Self = @This();
    w,
    x,

    pub fn from(x: anytype) Self {
        if (@typeInfo(@TypeOf(x)) != .Int) @compileError("Incorrect type passed into Width.from");
        return @intToEnum(Self, x & 0x1);
    }
};

pub fn Field(comptime ty: type, comptime mem: anytype) type {
    comptime {
        return std.meta.fieldInfo(ty, mem).field_type;
    }
}

pub fn bytes(T: type, int: anytype) T {
    return std.mem.readIntSliceLittle(T, &std.mem.toBytes(int));
}
