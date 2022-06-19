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
            .mov => |mov| try std.fmt.format(writer, "mov{s} {}, #0x{x}", .{ @tagName(mov.ext), mov.rd, mov.imm16 }),
            .@"and", .bic, .orr, .orn, .eor, .eon => |log| try std.fmt.format(writer, "{s}{}", .{ @tagName(self.*), log }),
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
        imm12: u12,
        imm_tag: struct {
            uimm6: u6,
            uimm4: u4,
        },
        carry: Register,
    },
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
        const s = if (self.s) "s" else " ";
        var buf: [100:0]u8 = undefined;
        const p = switch (self.payload) {
            .imm => |imm| std.fmt.bufPrintZ(
                &buf,
                "#0x{x}",
                .{self.decodeBitMasks(imm.imms, imm.immr)},
            ) catch unreachable,
            else => std.debug.todo(""),
        };
        try std.fmt.format(writer, "{s} {s}, {s}, {s}", .{
            s,
            @tagName(self.rd),
            @tagName(self.rn),
            p,
        });
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
        const thing: u32 = 0x7fffffff;
        const ones = (imms + 1) & (thing >> @truncate(u5, leading_zeroes));
        const mask = lookup[leading_zeroes - 25];
        const ret = std.math.rotr(u64, mask ^ (mask << @truncate(u6, ones)), @intCast(u32, immr));
        return if (self.width == .w)
            @truncate(u32, ret)
        else
            ret;
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
    rd: Register,
    immhi: u19,
    immlo: u2,
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
    ext: enum(u2) {
        signed = 0b00,
        none = 0b01,
        unsigned = 0b10,
    },
    immr: u6,
    imms: u6,
    rn: Register,
    rd: Register,
};

pub const ExtractInstr = struct {
    rm: Register,
    imms: u6,
    rn: Register,
    rd: Register,
};
