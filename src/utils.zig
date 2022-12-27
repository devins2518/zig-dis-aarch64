const std = @import("std");

pub const Register = struct {
    const Self = @This();
    reg: u5,
    width: Width,
    sp: bool,

    pub fn from(enc: anytype, width: Width, sp: bool) Self {
        const reg = @truncate(u5, enc);
        return Self{ .reg = reg, .width = width, .sp = sp };
    }

    pub fn toInt(self: *const Self) u5 {
        return self.reg;
    }

    pub fn format(self: *const Self, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        if (self.reg == 31 and self.width == .w and self.sp)
            try std.fmt.format(writer, "wsp", .{})
        else if (self.reg == 31 and self.width == .w and !self.sp)
            try std.fmt.format(writer, "wzr", .{})
        else if (self.reg == 31 and self.width == .x and self.sp)
            try std.fmt.format(writer, "sp", .{})
        else if (self.reg == 31 and self.width == .x and !self.sp)
            try std.fmt.format(writer, "xzr", .{})
        else
            try std.fmt.format(writer, "{s}{}", .{ @tagName(self.width), self.reg });
    }

    pub fn getWidth(self: Self) Width {
        return self.width;
    }

    pub fn eq(self: *const Self, other: *const Self) bool {
        return self.reg == other.reg and self.width == other.width and self.sp == other.sp;
    }
};

pub const Width = enum {
    const Self = @This();
    w,
    x,
    b,
    h,
    s,
    d,
    q,
    v,

    pub fn from(x: anytype) Self {
        if (@typeInfo(@TypeOf(x)) != .Int) @compileError("Incorrect type passed into Width.from");
        return @intToEnum(Self, x & 0x1);
    }
};

pub fn matches(imm: anytype, comptime _match: []const u8) bool {
    const ImmType = @TypeOf(imm);
    const imm_size = @bitSizeOf(ImmType);
    comptime {
        const ImmInfo = @typeInfo(ImmType);
        if (ImmInfo != .Int) @compileError("matches must be provided an integer type, found" ++ @typeName(ImmType));
        if (_match.len != imm_size + 2) @compileError("matches must be provided a string which is the length of imm with a `0b` prefix");
    }
    const match = _match[2..];

    comptime var start_pos: usize = std.mem.indexOfAnyPos(u8, match, 0, &.{ '0', '1' }) orelse return true;
    comptime var end_pos: usize = std.mem.indexOfScalarPos(u8, match, start_pos, 'x') orelse match.len;
    inline while (true) {
        const bits_str = match[start_pos..end_pos];

        const len = bits_str.len;
        const LenType = std.meta.Int(.unsigned, len);

        const shift = imm_size - end_pos;

        const bits = comptime std.fmt.parseUnsigned(LenType, bits_str, 2) catch unreachable;

        if (@truncate(LenType, imm >> shift) != bits)
            return false;
        start_pos = comptime std.mem.indexOfAnyPos(u8, match, end_pos, &.{ '0', '1' }) orelse return true;
        end_pos = comptime std.mem.indexOfScalarPos(u8, match, start_pos, 'x') orelse match.len;
    }
}

pub fn Field(comptime ty: type, comptime mem: anytype) type {
    return comptime std.meta.fieldInfo(ty, mem).type;
}

test "matches" {
    try std.testing.expect(matches(@as(u3, 0b111), "0bxxx"));
    try std.testing.expect(matches(@as(u3, 0b111), "0bxx1"));
    try std.testing.expect(matches(@as(u3, 0b111), "0bx1x"));
    try std.testing.expect(matches(@as(u3, 0b111), "0bx11"));
    try std.testing.expect(matches(@as(u3, 0b111), "0b1xx"));
    try std.testing.expect(matches(@as(u3, 0b111), "0b1x1"));
    try std.testing.expect(matches(@as(u3, 0b111), "0b11x"));
    try std.testing.expect(matches(@as(u3, 0b111), "0b111"));

    try std.testing.expect(matches(@as(u3, 0b000), "0bxxx"));
    try std.testing.expect(matches(@as(u3, 0b001), "0bxx1"));
    try std.testing.expect(matches(@as(u3, 0b010), "0bx1x"));
    try std.testing.expect(matches(@as(u3, 0b011), "0bx11"));
    try std.testing.expect(matches(@as(u3, 0b100), "0b1xx"));
    try std.testing.expect(matches(@as(u3, 0b101), "0b1x1"));
    try std.testing.expect(matches(@as(u3, 0b110), "0b11x"));
    try std.testing.expect(matches(@as(u3, 0b111), "0b111"));

    try std.testing.expect(!matches(@as(u3, 0b110), "0bxx1"));
    try std.testing.expect(!matches(@as(u3, 0b101), "0bx1x"));
    try std.testing.expect(!matches(@as(u3, 0b100), "0bx11"));
    try std.testing.expect(!matches(@as(u3, 0b011), "0b1xx"));
    try std.testing.expect(!matches(@as(u3, 0b010), "0b1x1"));
    try std.testing.expect(!matches(@as(u3, 0b001), "0b11x"));
    try std.testing.expect(!matches(@as(u3, 0b000), "0b111"));

    try std.testing.expect(matches(@as(u5, 0b11111), "0bxxxxx"));
    try std.testing.expect(matches(@as(u5, 0b11111), "0bxxxx1"));
    try std.testing.expect(matches(@as(u5, 0b11111), "0bxxx1x"));
    try std.testing.expect(matches(@as(u5, 0b11111), "0bxxx11"));
    try std.testing.expect(matches(@as(u5, 0b11111), "0bxx1xx"));
    try std.testing.expect(matches(@as(u5, 0b11111), "0bxx1x1"));
    try std.testing.expect(matches(@as(u5, 0b11111), "0bxx11x"));
    try std.testing.expect(matches(@as(u5, 0b11111), "0bxx111"));
    try std.testing.expect(matches(@as(u5, 0b11111), "0bx1xxx"));
    try std.testing.expect(matches(@as(u5, 0b11111), "0bx1xx1"));
    try std.testing.expect(matches(@as(u5, 0b11111), "0bx1x1x"));
    try std.testing.expect(matches(@as(u5, 0b11111), "0bx1x11"));
    try std.testing.expect(matches(@as(u5, 0b11111), "0bx11xx"));
    try std.testing.expect(matches(@as(u5, 0b11111), "0bx11x1"));
    try std.testing.expect(matches(@as(u5, 0b11111), "0bx111x"));
    try std.testing.expect(matches(@as(u5, 0b11111), "0bx1111"));
    try std.testing.expect(matches(@as(u5, 0b11111), "0b1xxxx"));
    try std.testing.expect(matches(@as(u5, 0b11111), "0b1xxx1"));
    try std.testing.expect(matches(@as(u5, 0b11111), "0b1xx1x"));
    try std.testing.expect(matches(@as(u5, 0b11111), "0b1xx11"));
    try std.testing.expect(matches(@as(u5, 0b11111), "0b1x1xx"));
    try std.testing.expect(matches(@as(u5, 0b11111), "0b1x1x1"));
    try std.testing.expect(matches(@as(u5, 0b11111), "0b1x11x"));
    try std.testing.expect(matches(@as(u5, 0b11111), "0b1x111"));
    try std.testing.expect(matches(@as(u5, 0b11111), "0b11xxx"));
    try std.testing.expect(matches(@as(u5, 0b11111), "0b11xx1"));
    try std.testing.expect(matches(@as(u5, 0b11111), "0b11x1x"));
    try std.testing.expect(matches(@as(u5, 0b11111), "0b11x11"));
    try std.testing.expect(matches(@as(u5, 0b11111), "0b111xx"));
    try std.testing.expect(matches(@as(u5, 0b11111), "0b111x1"));
    try std.testing.expect(matches(@as(u5, 0b11111), "0b1111x"));
    try std.testing.expect(matches(@as(u5, 0b11111), "0b11111"));

    try std.testing.expect(matches(@as(u5, 0b00000), "0bxxxxx"));
    try std.testing.expect(matches(@as(u5, 0b00001), "0bxxxx1"));
    try std.testing.expect(matches(@as(u5, 0b00010), "0bxxx1x"));
    try std.testing.expect(matches(@as(u5, 0b00011), "0bxxx11"));
    try std.testing.expect(matches(@as(u5, 0b00100), "0bxx1xx"));
    try std.testing.expect(matches(@as(u5, 0b00101), "0bxx1x1"));
    try std.testing.expect(matches(@as(u5, 0b00110), "0bxx11x"));
    try std.testing.expect(matches(@as(u5, 0b00111), "0bxx111"));
    try std.testing.expect(matches(@as(u5, 0b01000), "0bx1xxx"));
    try std.testing.expect(matches(@as(u5, 0b01001), "0bx1xx1"));
    try std.testing.expect(matches(@as(u5, 0b01010), "0bx1x1x"));
    try std.testing.expect(matches(@as(u5, 0b01011), "0bx1x11"));
    try std.testing.expect(matches(@as(u5, 0b01100), "0bx11xx"));
    try std.testing.expect(matches(@as(u5, 0b01101), "0bx11x1"));
    try std.testing.expect(matches(@as(u5, 0b01110), "0bx111x"));
    try std.testing.expect(matches(@as(u5, 0b01111), "0bx1111"));
    try std.testing.expect(matches(@as(u5, 0b10000), "0b1xxxx"));
    try std.testing.expect(matches(@as(u5, 0b10001), "0b1xxx1"));
    try std.testing.expect(matches(@as(u5, 0b10010), "0b1xx1x"));
    try std.testing.expect(matches(@as(u5, 0b10011), "0b1xx11"));
    try std.testing.expect(matches(@as(u5, 0b10100), "0b1x1xx"));
    try std.testing.expect(matches(@as(u5, 0b10101), "0b1x1x1"));
    try std.testing.expect(matches(@as(u5, 0b10110), "0b1x11x"));
    try std.testing.expect(matches(@as(u5, 0b10111), "0b1x111"));
    try std.testing.expect(matches(@as(u5, 0b11000), "0b11xxx"));
    try std.testing.expect(matches(@as(u5, 0b11001), "0b11xx1"));
    try std.testing.expect(matches(@as(u5, 0b11010), "0b11x1x"));
    try std.testing.expect(matches(@as(u5, 0b11011), "0b11x11"));
    try std.testing.expect(matches(@as(u5, 0b11100), "0b111xx"));
    try std.testing.expect(matches(@as(u5, 0b11101), "0b111x1"));
    try std.testing.expect(matches(@as(u5, 0b11110), "0b1111x"));
    try std.testing.expect(matches(@as(u5, 0b11111), "0b11111"));

    try std.testing.expect(!matches(@as(u5, 0b11110), "0bxxxx1"));
    try std.testing.expect(!matches(@as(u5, 0b11101), "0bxxx1x"));
    try std.testing.expect(!matches(@as(u5, 0b11100), "0bxxx11"));
    try std.testing.expect(!matches(@as(u5, 0b11011), "0bxx1xx"));
    try std.testing.expect(!matches(@as(u5, 0b11010), "0bxx1x1"));
    try std.testing.expect(!matches(@as(u5, 0b11001), "0bxx11x"));
    try std.testing.expect(!matches(@as(u5, 0b11000), "0bxx111"));
    try std.testing.expect(!matches(@as(u5, 0b10111), "0bx1xxx"));
    try std.testing.expect(!matches(@as(u5, 0b10110), "0bx1xx1"));
    try std.testing.expect(!matches(@as(u5, 0b10101), "0bx1x1x"));
    try std.testing.expect(!matches(@as(u5, 0b10100), "0bx1x11"));
    try std.testing.expect(!matches(@as(u5, 0b10011), "0bx11xx"));
    try std.testing.expect(!matches(@as(u5, 0b10010), "0bx11x1"));
    try std.testing.expect(!matches(@as(u5, 0b10001), "0bx111x"));
    try std.testing.expect(!matches(@as(u5, 0b10000), "0bx1111"));
    try std.testing.expect(!matches(@as(u5, 0b01111), "0b1xxxx"));
    try std.testing.expect(!matches(@as(u5, 0b01110), "0b1xxx1"));
    try std.testing.expect(!matches(@as(u5, 0b01101), "0b1xx1x"));
    try std.testing.expect(!matches(@as(u5, 0b01100), "0b1xx11"));
    try std.testing.expect(!matches(@as(u5, 0b01011), "0b1x1xx"));
    try std.testing.expect(!matches(@as(u5, 0b01010), "0b1x1x1"));
    try std.testing.expect(!matches(@as(u5, 0b01001), "0b1x11x"));
    try std.testing.expect(!matches(@as(u5, 0b01000), "0b1x111"));
    try std.testing.expect(!matches(@as(u5, 0b00111), "0b11xxx"));
    try std.testing.expect(!matches(@as(u5, 0b00110), "0b11xx1"));
    try std.testing.expect(!matches(@as(u5, 0b00101), "0b11x1x"));
    try std.testing.expect(!matches(@as(u5, 0b00100), "0b11x11"));
    try std.testing.expect(!matches(@as(u5, 0b00011), "0b111xx"));
    try std.testing.expect(!matches(@as(u5, 0b00010), "0b111x1"));
    try std.testing.expect(!matches(@as(u5, 0b00001), "0b1111x"));
    try std.testing.expect(!matches(@as(u5, 0b00000), "0b11111"));
}
