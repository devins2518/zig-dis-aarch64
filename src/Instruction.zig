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
    subp: DataProcInstr,
    irg: DataProcInstr,
    gmi: DataProcInstr,
    pacga: DataProcInstr,
    subps: DataProcInstr,
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

    // Branch
    // Conditional branch (immediate)
    bcond: BranchCondInstr,
    bccond: BranchCondInstr,
    // Exception generation
    svc: ExceptionInstr,
    hvc: ExceptionInstr,
    smc: ExceptionInstr,
    brk: ExceptionInstr,
    hlt: ExceptionInstr,
    tcancel: ExceptionInstr,
    dcps1: ExceptionInstr,
    dcps2: ExceptionInstr,
    dcps3: ExceptionInstr,
    // System instructions with register argument
    wfet: SysWithRegInstr,
    wfit: SysWithRegInstr,
    // Hints
    hint,
    nop,
    yield,
    wfe,
    wfi,
    sev,
    sevl,
    dgh,
    xpac,
    pacia1716,
    pacib1716,
    autia1716,
    autib1716,
    esb,
    psb_csync,
    tsb_csync,
    csdb,
    paciaz,
    paciasp,
    pacibz,
    pacibsp,
    autiaz,
    autiasp,
    autibz,
    autibsp,
    bti,
    // Barriers
    // PSTATE
    // System with result
    // System instructions
    // System register move
    // Unconditional branch (register)
    br: BranchInstr,
    blr: BranchInstr,
    ret: BranchInstr,
    eret,
    drps,
    // Unconditional branch (immediate)
    b: BranchInstr,
    bl: BranchInstr,
    // Compare and branch (immediate)
    cbz: CompBranchInstr,
    cbnz: CompBranchInstr,
    // Test and branch (immediate)
    tbz: TestInstr,
    tbnz: TestInstr,

    pub fn fmtPrint(self: *const Self, writer: anytype) !void {
        switch (self.*) {
            .mov => |mov| try std.fmt.format(writer, "{}", .{mov}),
            .@"and", .bic, .orr, .orn, .eor, .eon => |log| try std.fmt.format(writer, "{}", .{log}),
            .adr, .adrp => |log| try std.fmt.format(writer, "{s} {}", .{ @tagName(self.*), log }),
            .add, .adc, .sub, .sbc => |addsub| try std.fmt.format(writer, "{}", .{addsub}),
            .bfm => |bfm| try std.fmt.format(writer, "{}", .{bfm}),
            .extr => |extr| try std.fmt.format(writer, "extr {}, {}, {}, #{}", .{ extr.rd, extr.rn, extr.rm, extr.imms }),
            .crc32x,
            .crc32cx,
            .crc32b,
            .crc32cb,
            .crc32h,
            .crc32ch,
            .crc32w,
            .crc32cw,
            => |instr| {
                const rd = if (instr.rd.getWidth() == .x) instr.rd.toOther() else instr.rd;
                const rn = if (instr.rn.getWidth() == .x) instr.rn.toOther() else instr.rn;
                try std.fmt.format(writer, "{s} {}, {}, {}", .{
                    @tagName(self.*),
                    rd,
                    rn,
                    instr.rm.?,
                });
            },
            .udiv,
            .sdiv,
            .lslv,
            .lsrv,
            .asrv,
            .rorv,
            .subp,
            .irg,
            .gmi,
            .pacga,
            .subps,
            => |instr| {
                const name = if (self.* == .asrv)
                    "asr"
                else if (self.* == .lslv)
                    "lsl"
                else if (self.* == .lsrv)
                    "lsr"
                else if (self.* == .rorv)
                    "ror"
                else
                    @tagName(self.*);
                try std.fmt.format(writer, "{s} {}, {}, {}", .{
                    name,
                    instr.rd,
                    instr.rn,
                    instr.rm.?,
                });
            },
            .rbit,
            .clz,
            .cls,
            .rev,
            .rev16,
            .rev32,
            => |instr| try std.fmt.format(writer, "{s} {}, {}", .{
                @tagName(self.*),
                instr.rd,
                instr.rn,
            }),
            .madd,
            .smaddl,
            .umaddl,
            .msub,
            .smsubl,
            .umsubl,
            .smulh,
            .umulh,
            => |instr| {
                if (self.* == .smulh or self.* == .umulh)
                    try std.fmt.format(writer, "{s} {}, {}, {}", .{
                        @tagName(self.*),
                        instr.rd,
                        instr.rn,
                        instr.rm.?,
                    })
                else
                    try std.fmt.format(writer, "{s} {}, {}, {}, {}", .{
                        @tagName(self.*),
                        instr.rd,
                        instr.rn,
                        instr.rm.?,
                        instr.ra.?,
                    });
            },
            .ccmn, .ccmp => |instr| try std.fmt.format(writer, "{s} {}", .{ @tagName(self.*), instr }),
            .csel,
            .csinc,
            .csinv,
            .csneg,
            => |instr| try std.fmt.format(writer, "{s} {}, {}, {}, {s}", .{
                @tagName(self.*),
                instr.rd,
                instr.rn,
                instr.rm,
                @tagName(instr.cond),
            }),
            .ret, .br, .blr => |instr| {
                try std.fmt.format(writer, "{s}", .{@tagName(self.*)});
                const reg_int = instr.reg.toInt();
                if (self.* != .ret or reg_int != 30)
                    try std.fmt.format(writer, " {}", .{instr.reg});
            },
            .tbz, .tbnz => |instr| {
                try std.fmt.format(writer, "{s}", .{@tagName(self.*)});
                const r = if (instr.b5 == 0) "w" else "x";
                const t = instr.rt.toInt();
                const imm = @as(u6, instr.b5) << 5 | instr.b40;
                try std.fmt.format(writer, " {s}{}, #{}, #{}", .{ r, t, imm, @bitCast(i16, @as(u16, instr.imm14) << 2) });
            },
            .svc,
            .hvc,
            .smc,
            .brk,
            .hlt,
            .tcancel,
            .dcps1,
            .dcps2,
            .dcps3,
            => |instr| try std.fmt.format(writer, "{s} #0x{x}", .{ @tagName(self.*), instr.imm16 }),
            .b, .bl => |instr| {
                switch (instr) {
                    .imm => |imm| try std.fmt.format(writer, "{s} #{}", .{ @tagName(self.*), @bitCast(i28, @as(u28, imm) << 2) }),
                    .reg => |reg| try std.fmt.format(writer, "{s} {}", .{ @tagName(self.*), reg }),
                }
            },
            .bcond, .bccond => |instr| {
                if (self.* == .bcond)
                    try std.fmt.format(writer, "b", .{})
                else
                    try std.fmt.format(writer, "bc", .{});
                try std.fmt.format(writer, ".{s} #{}", .{ @tagName(instr.cond), @bitCast(i21, @as(u21, instr.imm19) << 2) });
            },
            .cbz, .cbnz => |instr| try std.fmt.format(writer, "{s} {}, #{}", .{ @tagName(self.*), instr.rt, @bitCast(i21, @as(u21, instr.imm19) << 2) }),
            else => try std.fmt.format(writer, "{s}", .{@tagName(self.*)}),
        }
    }
};

pub const AddSubInstr = struct {
    s: bool,
    op: enum { add, sub, adc, sbc },
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
        // TODO: modularize this
        shift_reg: struct {
            rm: Register,
            imm6: u6,
            shift: u2,
        },
        ext_reg: struct {
            rm: Register,
            option: u3,
            imm3: u3,
        },
    },

    pub fn format(self: *const @This(), comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        const s = if (self.s) "s" else "";
        if (self.op == .add and self.s and self.rd.reg == 31)
            try std.fmt.format(writer, "cmn {}, ", .{self.rn})
        else if (self.op == .sub and self.s and self.rd.reg == 31)
            try std.fmt.format(writer, "cmp {}, ", .{self.rn})
        else
            try std.fmt.format(writer, "{s}{s} {}, {}, ", .{
                @tagName(self.op),
                s,
                self.rd,
                self.rn,
            });

        switch (self.payload) {
            .imm12 => |imm| {
                try std.fmt.format(writer, "#{}", .{imm.imm});
                if (imm.sh == 1)
                    try std.fmt.format(writer, ", lsl #12", .{});
            },
            .imm_tag => std.debug.todo("imm tag"),
            .carry => |rm| try std.fmt.format(writer, "{}", .{rm}),
            .shift_reg => |shift| {
                try std.fmt.format(writer, "{s}", .{shift.rm});
                if (shift.imm6 != 0) switch (shift.shift) {
                    0b00 => try std.fmt.format(writer, ", lsl #{}", .{shift.imm6}),
                    0b01 => try std.fmt.format(writer, ", lsr #{}", .{shift.imm6}),
                    0b10 => try std.fmt.format(writer, ", asr #{}", .{shift.imm6}),
                    0b11 => unreachable,
                };
            },
            .ext_reg => |ext| {
                const option = switch (ext.option) {
                    0b000 => "uxtb",
                    0b001 => "uxth",
                    0b010 => if (self.width == .w and
                        ((self.rn.reg == 31 and self.rn.sp) or
                        (self.rd.reg == 31 and self.rd.sp)))
                        if (ext.imm3 == 0x0) "" else "lsl"
                    else
                        "uxtw",
                    0b011 => if (self.width == .x and
                        ((self.rn.reg == 31 and self.rn.sp) or
                        (self.rd.reg == 31 and self.rd.sp)))
                        if (ext.imm3 == 0x0) "" else "lsl"
                    else
                        "uxtx",
                    0b100 => "sxtb",
                    0b101 => "sxth",
                    0b110 => "sxtw",
                    0b111 => "sxtx",
                };
                if (self.width == .w)
                    try std.fmt.format(writer, "{s}", .{ext.rm})
                else {
                    const r = switch (ext.option) {
                        0b011, 0b111 => "x",
                        else => "w",
                    };
                    var m_buf: [2:0]u8 = undefined;
                    const m_int = ext.rm.toInt();
                    const m = if (m_int == 0b11111)
                        "zr"
                    else
                        std.fmt.bufPrintZ(&m_buf, "{}", .{m_int});
                    try std.fmt.format(writer, "{s}{s}", .{
                        r,
                        m,
                    });
                }

                if (!(std.mem.eql(u8, "lsl", option) or std.mem.eql(u8, "", option)) and ext.imm3 == 0) {
                    try std.fmt.format(writer, ", {s}", .{option});
                    if (ext.imm3 != 0)
                        try std.fmt.format(writer, " #0x{x}", .{ext.imm3});
                }
            },
        }
    }
};

pub const LogInstr = struct {
    s: bool,
    n: u1,
    op: enum { @"and", bic, orr, orn, eor, eon },
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
            shift: u2,
        },
    },

    pub fn format(self: *const @This(), comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        if (self.op == .@"and" and self.s and self.rd.toInt() == 0b11111) {
            try std.fmt.format(writer, "tst {}, ", .{self.rn});
        } else {
            const s = if (self.s) "s" else "";
            try std.fmt.format(writer, "{s}{s} {}, {}, ", .{
                @tagName(self.op),
                s,
                self.rd,
                self.rn,
            });
        }
        switch (self.payload) {
            .imm => |imm| try std.fmt.format(writer, "#0x{x}", .{self.decodeBitMasks(imm.imms, imm.immr)}),
            .shift_reg => |shift| {
                try std.fmt.format(writer, "{s}", .{shift.rm});
                if (shift.imm6 != 0) switch (shift.shift) {
                    0b00 => try std.fmt.format(writer, ", lsl #{}", .{shift.imm6}),
                    0b01 => try std.fmt.format(writer, ", lsr #{}", .{shift.imm6}),
                    0b10 => try std.fmt.format(writer, ", asr #{}", .{shift.imm6}),
                    0b11 => try std.fmt.format(writer, ", ror #{}", .{shift.imm6}),
                };
            },
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

        const pattern = (@intCast(u32, self.n) << 6) | @truncate(u6, ~imms);

        if ((pattern & (pattern - 1)) == 0) @panic("decode failure");

        const leading_zeroes = @clz(u32, pattern);
        const ones = (imms + 1) & (@as(u32, 0x7fffffff) >> @truncate(u5, leading_zeroes));
        const mask = lookup[leading_zeroes - 25];
        const ret = std.math.rotr(u64, mask ^ (mask << @truncate(u6, ones)), @as(u32, immr));
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

    pub fn format(self: *const @This(), comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        try std.fmt.format(writer, "{}, ", .{self.rn});
        switch (self.payload) {
            .imm5 => |imm| try std.fmt.format(writer, "#{}", .{imm}),
            .rm => |rm| try std.fmt.format(writer, "{}", .{rm}),
        }
        try std.fmt.format(writer, ", #{}, {s}", .{ self.nzcv, @tagName(self.cond) });
    }
};

pub const ConSelectInstr = struct {
    rm: Register,
    cond: Condition,
    rn: Register,
    rd: Register,
};

pub const DataProcInstr = struct {
    rm: ?Register = null,
    ra: ?Register = null,
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
        try std.fmt.format(writer, "{}, #{}", .{
            self.rd,
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
    width: Width,
    hw: u2,
    imm16: u16,
    rd: Register,

    pub fn format(self: *const @This(), comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        try std.fmt.format(writer, "mov{s} {}, #{}", .{ @tagName(self.ext), self.rd, self.imm16 });
        if (self.width == .w and self.hw != 0)
            try std.fmt.format(writer, ", lsl #16", .{})
        else if (self.width == .x and self.hw != 0)
            try std.fmt.format(writer, ", lsl #{}", .{@intCast(u64, self.hw) * 16});
    }
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
            else if (self.bfxPreferred())
                "sbfx"
            else if (self.imms == 0b011111 or self.imms == 0b111111)
                "asr"
            else if (self.immr == 0b000000 and self.imms == 0b000111)
                "sxtb"
            else if (self.immr == 0b000000 and self.imms == 0b001111)
                "sxth"
            else if (self.immr == 0b000000 and self.imms == 0b011111)
                "sxtw"
            else
                unreachable,
            .unsigned => if (self.imms < self.immr)
                "ubfiz"
            else if (self.bfxPreferred())
                "ubfx"
            else if ((self.imms != 0b011111 or self.imms != 0b111111) and @intCast(u7, self.imms) + 1 == self.immr)
                "lsl"
            else if (self.imms == 0b011111 or self.imms == 0b111111)
                "lsr"
            else if (self.immr == 0b000000 and self.imms == 0b000111)
                "uxtb"
            else if (self.immr == 0b000000 and self.imms == 0b001111)
                "uxth"
            else
                unreachable,
            .none => if (self.imms < self.immr)
                if (self.rn.reg == 31 or self.rn.reg == 31) "bfc" else "bfi"
            else
                "bfxil",
        };
        if (self.imms < self.immr)
            try std.fmt.format(writer, "{s} {}, {}, #{}, #{}", .{
                name,
                self.rd,
                self.rn,
                width - self.immr,
                self.imms + 1,
            })
        else
            try std.fmt.format(writer, "{s} {}, {}, #{}, #{}", .{
                name,
                self.rd,
                self.rn,
                self.immr,
                self.imms,
            });
    }

    fn bfxPreferred(self: *const @This()) bool {
        const imms = self.imms;
        const immr = self.immr;
        return !((imms != 0b011111 and @intCast(u7, imms) + 1 == immr) or
            (imms != 0b111111 and @intCast(u7, imms) + 1 == immr) or
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

pub const BranchCondInstr = struct {
    imm19: u19,
    cond: Condition,
};

pub const ExceptionInstr = struct {
    imm16: u16,
};

pub const SysWithRegInstr = struct {
    rd: Register,
};

pub const BranchInstr = union(enum) {
    imm: u26,
    reg: Register,
};

pub const TestInstr = struct {
    b5: u1,
    b40: u5,
    imm14: u14,
    rt: Register,
};

pub const CompBranchInstr = struct {
    imm19: u19,
    rt: Register,
};
