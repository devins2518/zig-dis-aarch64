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

    pub fn toOther(self: Self) Self {
        const other_width = if (self.width == .w) Width.x else Width.w;
        return Self{ .reg = self.reg, .width = other_width, .sp = self.sp };
    }

    pub fn getWidth(self: Self) Width {
        return self.width;
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
