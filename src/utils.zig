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

pub fn Field(comptime ty: type, comptime mem: anytype) type {
    return comptime std.meta.fieldInfo(ty, mem).field_type;
}
