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

    pub fn from(enc: anytype, width: Width, sp: bool) Self {
        const reg = @truncate(u5, enc);
        const x = width == .x;
        return switch (reg) {
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

    pub fn toInt(self: *const Self) u5 {
        return switch (self.*) {
            .x0, .w0 => 0b00000,
            .x1, .w1 => 0b00001,
            .x2, .w2 => 0b00010,
            .x3, .w3 => 0b00011,
            .x4, .w4 => 0b00100,
            .x5, .w5 => 0b00101,
            .x6, .w6 => 0b00110,
            .x7, .w7 => 0b00111,
            .x8, .w8 => 0b01000,
            .x9, .w9 => 0b01001,
            .x10, .w10 => 0b01010,
            .x11, .w11 => 0b01011,
            .x12, .w12 => 0b01100,
            .x13, .w13 => 0b01101,
            .x14, .w14 => 0b01110,
            .x15, .w15 => 0b01111,
            .x16, .w16 => 0b10000,
            .x17, .w17 => 0b10001,
            .x18, .w18 => 0b10010,
            .x19, .w19 => 0b10011,
            .x20, .w20 => 0b10100,
            .x21, .w21 => 0b10101,
            .x22, .w22 => 0b10110,
            .x23, .w23 => 0b10111,
            .x24, .w24 => 0b11000,
            .x25, .w25 => 0b11001,
            .x26, .w26 => 0b11010,
            .x27, .w27 => 0b11011,
            .x28, .w28 => 0b11100,
            .x29, .w29 => 0b11101,
            .x30, .w30 => 0b11110,
            .sp, .xzr, .wsp, .wzr => 0b11111,
        };
    }

    pub fn format(self: *const Self, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        try writer.writeAll(@tagName(self.*));
    }

    pub fn toOther(self: Self) Self {
        return switch (self) {
            // zig fmt: off
            .w0 => .x0, .w1 => .x1, .w2 => .x2, .w3 => .x3, .w4 => .x4,
            .w5 => .x5, .w6 => .x6, .w7 => .x7, .w8 => .x8, .w9 => .x9,
            .w10 => .x10, .w11 => .x11, .w12 => .x12, .w13 => .x13, .w14 => .x14,
            .w15 => .x15, .w16 => .x16, .w17 => .x17, .w18 => .x18, .w19 => .x19,
            .w20 => .x20, .w21 => .x21, .w22 => .x22, .w23 => .x23, .w24 => .x24,
            .w25 => .x25, .w26 => .x26, .w27 => .x27, .w28 => .x28, .w29 => .x29,
            .w30 => .x30, .wsp => .sp, .wzr => .xzr,
            .x0 => .w0, .x1 => .w1, .x2 => .w2, .x3 => .w3, .x4 => .w4,
            .x5 => .w5, .x6 => .w6, .x7 => .w7, .x8 => .w8, .x9 => .w9,
            .x10 => .w10, .x11 => .w11, .x12 => .w12, .x13 => .w13, .x14 => .w14,
            .x15 => .w15, .x16 => .w16, .x17 => .w17, .x18 => .w18, .x19 => .w19,
            .x20 => .w20, .x21 => .w21, .x22 => .w22, .x23 => .w23, .x24 => .w24,
            .x25 => .w25, .x26 => .w26, .x27 => .w27, .x28 => .w28, .x29 => .w29,
            .x30 => .w30, .sp => .wsp, .xzr => .wzr,
            // zig fmt: on
        };
    }

    pub fn getWidth(self: Self) Width {
        return switch (self) {
            // zig fmt: off
            .w0,  .w1,  .w2,  .w3,  .w4,  .w5,  .w6,  .w7,  .w8,  .w9,  .w10, .w11, .w12, .w13, .w14, .w15,
            .w16, .w17, .w18, .w19, .w20, .w21, .w22, .w23, .w24, .w25, .w26, .w27, .w28, .w29, .w30, .wzr,
            .wsp => Width.w,
            .x0,  .x1,  .x2,  .x3,  .x4,  .x5,  .x6,  .x7,  .x8,  .x9,  .x10, .x11, .x12, .x13, .x14, .x15,
            .x16, .x17, .x18, .x19, .x20, .x21, .x22, .x23, .x24, .x25, .x26, .x27, .x28, .x29, .x30, .xzr,
            .sp => Width.x,
            // zig fmt: on
        };
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
