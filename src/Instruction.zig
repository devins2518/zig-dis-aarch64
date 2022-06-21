const std = @import("std");
const Register = @import("utils.zig").Register;
const Width = @import("utils.zig").Width;

pub const Condition = enum(u4) {
    eq = 0x0,
    ne,
    cs,
    cc,
    mi,
    pl,
    vs,
    vc,
    hi,
    ls,
    ge,
    lt,
    gt,
    le,
    al,
    nev,
};

pub const Instruction = union(enum) {
    const Self = @This();
    // Data processing (immediate, register)
    // Logical
    @"and": LogInstr,
    bic: LogInstr,
    orr: LogInstr,
    orn: LogInstr,
    eor: LogInstr,
    eon: LogInstr,
    // Add/Sub (shifted, extended)
    add: AddSubInstr,
    sub: AddSubInstr,
    // Add/Sub (carry)
    adc: AddSubInstr,
    sbc: AddSubInstr,
    // Conditional compare (register, immediate)
    ccmn: ConCompInstr,
    ccmp: ConCompInstr,
    // Conditional select
    csel: ConSelectInstr,
    csinc: ConSelectInstr,
    csinv: ConSelectInstr,
    csneg: ConSelectInstr,
    // Data processing (3 source)
    madd: DataProcInstr,
    smaddl: DataProcInstr,
    umaddl: DataProcInstr,
    msub: DataProcInstr,
    smsubl: DataProcInstr,
    umsubl: DataProcInstr,
    smulh: DataProcInstr,
    umulh: DataProcInstr,
    // Data processing (2 source)
    crc32x: DataProcInstr,
    crc32cx: DataProcInstr,
    crc32b: DataProcInstr,
    crc32cb: DataProcInstr,
    crc32h: DataProcInstr,
    crc32ch: DataProcInstr,
    crc32w: DataProcInstr,
    crc32cw: DataProcInstr,
    udiv: DataProcInstr,
    sdiv: DataProcInstr,
    lslv: DataProcInstr,
    lsrv: DataProcInstr,
    asrv: DataProcInstr,
    rorv: DataProcInstr,
    // Data processing (1 source)
    rbit: DataProcInstr,
    clz: DataProcInstr,
    cls: DataProcInstr,
    rev: DataProcInstr,
    rev16: DataProcInstr,
    rev32: DataProcInstr,
    // PC relative addressing
    adr: PCRelAddrInstr,
    adrp: PCRelAddrInstr,
    // Move
    mov: MovInstr,
    // Bitfield
    bfm: BitfieldInstr,
    // Extract
    extr: ExtractInstr,

    pub fn fmtPrint(self: *const Self, writer: anytype) !void {
        switch (self.*) {
            .mov => |mov| try std.fmt.format(writer, "mov{s} {}, #{}", .{ @tagName(mov.ext), mov.rd, mov.imm16 }),
            .@"and", .bic, .orr, .orn, .eor, .eon => |log| try std.fmt.format(writer, "{s}{}", .{ @tagName(self.*), log }),
            .adr, .adrp => |log| try std.fmt.format(writer, "{s} {}", .{ @tagName(self.*), log }),
            .add, .sub => |addsub| try std.fmt.format(writer, "{s}{}", .{ @tagName(self.*), addsub }),
            .bfm => |bfm| try std.fmt.format(writer, "{}", .{bfm}),
            .extr => |extr| try std.fmt.format(writer, "extr {s}, {s}, {s}, #{}", .{
                @tagName(extr.rd),
                @tagName(extr.rn),
                @tagName(extr.rm),
                extr.imms,
            }),
            // TODO:
            // {add,sub}g
            else => std.debug.todo("fmt instruction"),
        }
    }
};

pub const AddSubInstr = struct {
    s: bool,
    width: Width,
    rn: Register,
    rd: Register,
    payload: union(enum) {
        imm12: struct {
            sh: u1,
            imm: u12,
        },
        imm_tag: struct {
            imm6: u6,
            imm4: u4,
        },
        carry: Register,
    },

    pub fn format(self: *const @This(), comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        const s = if (self.s) "s" else "";
        try std.fmt.format(writer, "{s} {s}, {s}", .{
            s,
            @tagName(self.rd),
            @tagName(self.rn),
        });

        switch (self.payload) {
            .imm12 => |imm| {
                try std.fmt.format(writer, ", #{}", .{imm.imm});
                if (imm.sh == 1)
                    try std.fmt.format(writer, ", lsl #12", .{});
            },
            .imm_tag => std.debug.todo(""),
            .carry => std.debug.todo(""),
        }
    }
};

pub const LogInstr = struct {
    s: bool,
    n: u1,
    width: Width,
    rn: Register,
    rd: Register,
    payload: union(enum) {
        imm: struct {
            immr: u6,
            imms: u6,
        },
        shift_reg: struct {
            rm: Register,
            imm6: u6,
        },
    },

    pub fn format(self: *const @This(), comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        const s = if (self.s) "s" else "";
        try std.fmt.format(writer, "{s} {s}, {s}, ", .{
            s,
            @tagName(self.rd),
            @tagName(self.rn),
        });
        switch (self.payload) {
            .imm => |imm| std.fmt.format(
                writer,
                "#{}",
                .{self.decodeBitMasks(imm.imms, imm.immr)},
            ) catch unreachable,
            else => unreachable,
        }
    }

    // https://dougallj.wordpress.com/2021/10/30/bit-twiddling-optimising-aarch64-logical-immediate-encoding-and-decoding/
    fn decodeBitMasks(self: *const @This(), imms: u6, immr: u6) u64 {
        const lookup = [_]u64{
            0xffffffffffffffff, // size = 64
            0x00000000ffffffff, // size = 32
            0x0000ffff0000ffff, // size = 16
            0x00ff00ff00ff00ff, // size = 8
            0x0f0f0f0f0f0f0f0f, // size = 4
            0x3333333333333333, // size = 2
        };

        const pattern: u32 = (@intCast(u32, self.n) << 6) | (~imms & 0x3f);

        if ((pattern & (pattern - 1)) == 0) @panic("decode failure");

        const leading_zeroes = @clz(u32, pattern);
        const ones = (imms + 1) & (@as(u32, 0x7fffffff) >> @truncate(u5, leading_zeroes));
        const mask = lookup[leading_zeroes - 25];
        const ret = std.math.rotr(u64, mask ^ (mask << @truncate(u6, ones)), @intCast(u32, immr));
        return if (self.width == .w) @truncate(u32, ret) else ret;
    }
};

pub const ConCompInstr = struct {
    cond: Condition,
    rn: Register,
    nzcv: u4,
    payload: union(enum) {
        imm5: u5,
        rm: Register,
    },
};

pub const ConSelectInstr = struct {
    rm: Register,
    cond: Condition,
    rn: Register,
    rd: Register,
};

pub const DataProcInstr = struct {
    rm: ?Register,
    ra: ?Register,
    rn: Register,
    rd: Register,
};

pub const PCRelAddrInstr = struct {
    p: bool,
    rd: Register,
    immhi: u19,
    immlo: u2,

    pub fn format(self: *const @This(), comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        var imm = @as(u64, self.immhi) << 2 | self.immlo;
        if (imm & (@as(u64, 1) << (21 - 1)) != 0)
            imm |= ~((@as(u64, 1) << 32) - 1);
        try std.fmt.format(writer, "{s}, #{}", .{
            @tagName(self.rd),
            imm,
        });
    }
};

pub const MovInstr = struct {
    ext: enum(u2) {
        n = 0b00,
        z = 0b10,
        k = 0b11,
    },
    imm16: u16,
    rd: Register,
};

pub const BitfieldInstr = struct {
    n: u1,
    width: Width,
    ext: enum(u2) {
        signed = 0b00,
        none = 0b01,
        unsigned = 0b10,
    },
    immr: u6,
    imms: u6,
    rn: Register,
    rd: Register,

    pub fn format(self: *const @This(), comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        const width: u8 = if (self.width == .w) 32 else 64;
        const name = switch (self.ext) {
            .signed => if (self.imms < self.immr)
                "sbfiz"
            else if (self.bfxPreferred()) "sbfx" else std.debug.todo("sbfm aliasing"),
            .unsigned => if (self.imms < self.immr)
                "ubfiz"
            else if (self.bfxPreferred()) "ubfx" else std.debug.todo("ubfm aliasing"),
            .none => if (self.imms < self.immr)
                if (self.rn == .wzr or self.rn == .xzr) "bfc" else "bfi"
            else
                "bfxil",
        };
        if (self.imms < self.immr)
            try std.fmt.format(writer, "{s} {s}, {s}, #{}, #{}", .{
                name,
                @tagName(self.rd),
                @tagName(self.rn),
                width - self.immr,
                self.imms + 1,
            })
        else
            try std.fmt.format(writer, "{s} {s}, {s}, #{}, #{}", .{
                name,
                @tagName(self.rd),
                @tagName(self.rn),
                self.immr,
                self.imms,
            });
    }

    fn bfxPreferred(self: *const @This()) bool {
        const imms = self.imms;
        const immr = self.immr;
        return !((imms != 0b011111 and imms + 1 == immr) or
            (imms != 0b111111 and imms + 1 == immr) or
            (imms == 0b011111) or
            (imms == 0b111111) or
            (immr == 0 and imms == 0b000111) or
            (immr == 0 and imms == 0b001111));
    }
};

pub const ExtractInstr = struct {
    rm: Register,
    imms: u6,
    rn: Register,
    rd: Register,
};
