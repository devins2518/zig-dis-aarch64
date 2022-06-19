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

    pub fn format(
        self: *const @This(),
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        const s = if (self.s) "s" else " ";
        var buf: [100:0]u8 = undefined;
        const p = switch (self.payload) {
            .imm => |imm| blk: {
                const mask = decodeBitMasks(self.n, imm.imms, imm.immr, self.width);
                break :blk std.fmt.bufPrintZ(&buf, "#0x{x}", .{mask}) catch unreachable;
            },
            else => std.debug.todo(""),
        };
        try std.fmt.format(writer, "{s} {s}, {s}, {s}", .{
            s,
            @tagName(self.rd),
            @tagName(self.rn),
            p,
        });
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

fn decodeBitMasks(immN: u1, imms: u6, immr: u6, width: Width) u64 {
    const len: u5 = @truncate(u5, 31 - @clz(u32, @as(u32, immN) << 6 | (~imms & 0x3f)));
    if (len < 1) @panic("decode failure");

    var size = @as(u32, 1) << len;
    const levels = size - 1;
    const s = imms & levels;
    const r = immr & levels;

    var ret: u64 = (@as(u64, 1) << @truncate(u6, s + 1)) - 1;
    var i: usize = 1;
    while (i <= r) : (i += 1) ret = std.math.rotr(u64, ret, size);

    if ((size == 32 and width == .w) or (size == 64 and width == .x)) {
        ret |= (ret << @truncate(u6, size));
        size *= 2;
    }

    if (width == .w) ret &= 0xFFFFFFFF;
    return ret;
}
