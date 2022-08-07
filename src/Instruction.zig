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
    clrex: u4,
    dsb: u4,
    dmb: u4,
    isb: u4,
    sb,
    tcommit,
    // PSTATE
    cfinv,
    xaflag,
    axflag,
    // System with result
    // System instructions
    sys: SysInstr,
    // System register move
    msr: SysRegMoveInstr,
    mrs: SysRegMoveInstr,
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

    // Data Processing (Scalar FP and SIMD)
    // Crypto AES
    aes: AesInstr,
    // Crypto SHA (2 and 3 register)
    sha1: ShaInstr,
    sha256: ShaInstr,
    // Advanced SIMD scalar copy
    dup,
    // Advanced SIMD scalar three same FP16
    fmulx,
    fcmeq,
    frecps,
    frsqrts,
    fcmge,
    facge,
    fabd,
    fcmgt,
    facgt,
    // Advanced SIMD two register misc FP16
    // Advanced SIMD three register extension
    // Advanced SIMD two register misc
    // Advanced SIMD across lanes
    // Advanced SIMD three different
    // Advanced SIMD three same
    // Advanced SIMD modified immediate
    // Advanced SIMD shift by immediate
    // Advanced SIMD vector x indexed element
    // Crypto three register, imm2
    // Crypto three register, SHA512
    // Crypto four register
    // XAR
    // Crypto two register SHA512
    // Conversion between floating point and fixed point
    // Conversion between floating point and integer
    // Floating point data processing (1 source)
    // Floating point compare
    // Floating point immediate
    // Floating point conditional compare
    // Floating point data processing (2 source)
    // Floating point conditional select
    // Floating point data processing (2 source)
    // Loads and Stores
    // Compare and swap pair
    // Advanced SIMD load/store multiple structures
    // Advanced SIMD load/store multiple structures (post indexed)
    // Advanced SIMD load/store single structures
    // Advanced SIMD load/store single structures (post indexed)
    // Load/store memory tags
    // Load/store exclusive pair
    st: LoadStoreInstr,
    ld: LoadStoreInstr,
    prfm: LoadStoreInstr,
    // Load/store exclusive register
    // Load/store ordered
    // Compare and swap
    // LDAPR/STLTR (unscaled immediate)
    // Load register (literal)
    // Memory copy and memory set
    // Load/store no-allocate pair (offset)
    // Load/store register pair (post-indexed)
    // Load/store register pair (offset)
    // Load/store register pair (pre-indexed)
    // Load/store register (unscaled immediate)
    // Load/store register (immediate post-indexed)
    // Load/store register (unprivileged)
    // Load/store register (immediate pre-indexed)
    // Atomic memory operations
    // Load/store register (register offset)
    // Load/store register (pac)
    // Load/store register (unsigned immediate)

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
                var rd = instr.rd;
                var rn = instr.rn;
                rd.width = .w;
                rn.width = .w;
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
            // TODO: multiple output styles
            // try std.fmt.format(writer, "{s}{s}.16b, {}, {}", .{ @tagName(self.*), @tagName(aes.op), aes.rd, aes.rn }),
            .aes => |aes| try std.fmt.format(writer, "{s}{s} {}.16b, {}.16b", .{ @tagName(self.*), @tagName(aes.op), aes.rd, aes.rn }),
            .sha1, .sha256 => |sha| if (sha.rm) |rm| switch (sha.op) {
                .c, .p, .m, .h, .h2 => try std.fmt.format(writer, "{s}{s} {}, {}, {}.4s", .{ @tagName(self.*), @tagName(sha.op), sha.rd, sha.rn, rm }),
                .su0 => try std.fmt.format(writer, "{s}{s} {}.4s, {}.4s, {}", .{ @tagName(self.*), @tagName(sha.op), sha.rd, sha.rn, rm }),
                .su1 => try std.fmt.format(writer, "{s}{s} {}.4s, {}.4s, {}.4s", .{ @tagName(self.*), @tagName(sha.op), sha.rd, sha.rn, rm }),
            } else switch (sha.op) {
                .h => try std.fmt.format(writer, "{s}{s} {}, {}", .{ @tagName(self.*), @tagName(sha.op), sha.rd, sha.rn }),
                .su0, .su1 => try std.fmt.format(writer, "{s}{s} {}.4s, {}.4s", .{ @tagName(self.*), @tagName(sha.op), sha.rd, sha.rn }),
                else => unreachable,
            },
            .ld, .st => |ldst| try std.fmt.format(writer, "{s}{s}{s}{s}{}", .{ @tagName(self.*), @tagName(ldst.ext), @tagName(ldst.op), @tagName(ldst.size), ldst }),
            .prfm => |prfm| {
                const rt = prfm.rt.toInt();
                const ty = switch (@truncate(u2, rt >> 3)) {
                    0b00 => "pld",
                    0b01 => "pli",
                    0b10 => "pst",
                    else => unreachable,
                };
                const target = switch (@truncate(u2, rt >> 1)) {
                    0b00 => "l1",
                    0b01 => "l2",
                    0b10 => "l3",
                    else => unreachable,
                };
                const policy = switch (@truncate(u1, rt)) {
                    0 => "keep",
                    1 => "strm",
                };
                try std.fmt.format(writer, "prf{s}m {s}{s}{s}, [{}", .{ @tagName(prfm.ext), ty, target, policy, prfm.rn });
                switch (prfm.payload) {
                    .imm12 => |imm| if (imm > 0) try std.fmt.format(writer, ", #{}", .{imm}),
                    .simm9 => |simm| if (simm > 0) try std.fmt.format(writer, ", #{}", .{@bitCast(i9, simm)}),
                    else => {},
                }
                try std.fmt.format(writer, "]", .{});
            },
            .clrex, .isb => |instr| {
                try std.fmt.format(writer, "{s}", .{@tagName(self.*)});
                if (instr != 0b1111)
                    try std.fmt.format(writer, " #{}", .{instr});
            },
            .dsb, .dmb => |instr| {
                const option = switch (instr) {
                    0b0000 => "#0",
                    0b0001 => "oshld",
                    0b0010 => "oshst",
                    0b0011 => "osh",
                    0b0100 => "#4",
                    0b0101 => "nshld",
                    0b0110 => "nshst",
                    0b0111 => "nsh",
                    0b1000 => "#8",
                    0b1001 => "ishld",
                    0b1010 => "ishst",
                    0b1011 => "ish",
                    0b1100 => "#12",
                    0b1101 => "ld",
                    0b1110 => "st",
                    0b1111 => "sy",
                };
                try std.fmt.format(writer, "{s} {s}", .{ @tagName(self.*), option });
            },
            .sys => |sys| try std.fmt.format(writer, "{}", .{sys}),
            .msr => |msr| {
                try std.fmt.format(writer, "{s} ", .{@tagName(self.*)});
                if (@truncate(u1, msr.o20) == 0) {
                    const pstate_field = if (msr.op1 == 0b000 and msr.op2 == 0b101)
                        "SPSel"
                    else if (msr.op1 == 0b011 and msr.op2 == 0b110)
                        "DAIFSet"
                    else if (msr.op1 == 0b011 and msr.op2 == 0b111)
                        "DAIFClr"
                    else if (msr.op1 == 0b000 and msr.op2 == 0b011)
                        "UAO"
                    else if (msr.op1 == 0b000 and msr.op2 == 0b100)
                        "PAN"
                    else if (msr.op1 == 0b001 and msr.op2 == 0b000 and msr.crm <= 0b0001)
                        "ALLINT"
                    else if (msr.op1 == 0b011 and msr.op2 == 0b001)
                        "SSBS"
                    else if (msr.op1 == 0b011 and msr.op2 == 0b010)
                        "DIT"
                    else if (msr.op1 == 0b011 and msr.op2 == 0b011 and @truncate(u3, msr.crm >> 1) == 0b001)
                        "SVCRSM"
                    else if (msr.op1 == 0b011 and msr.op2 == 0b011 and @truncate(u3, msr.crm >> 1) == 0b010)
                        "SVCRZA"
                    else if (msr.op1 == 0b011 and msr.op2 == 0b011 and @truncate(u3, msr.crm >> 1) == 0b011)
                        "SVCRSMZA"
                    else if (msr.op1 == 0b011 and msr.op2 == 0b100)
                        "TCO"
                    else
                        unreachable;
                    try std.fmt.format(writer, "{s}, #{}", .{ pstate_field, msr.crm });
                } else {
                    try msr.formatSysReg(writer);
                    try std.fmt.format(writer, ", {}", .{msr.rt});
                }
            },
            .mrs => |mrs| {
                try std.fmt.format(writer, "{s} ", .{@tagName(self.*)});
                try std.fmt.format(writer, "{}, ", .{mrs.rt});
                try mrs.formatSysReg(writer);
            },
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

pub const AesInstr = struct {
    rn: Register,
    rd: Register,
    op: enum { e, d, mc, imc },
};

pub const ShaInstr = struct {
    rn: Register,
    rd: Register,
    rm: ?Register,
    op: enum { c, p, m, su0, h, h2, su1 },
};

pub const LoadStoreInstr = struct {
    rn: Register,
    rt: Register,
    rt2: ?Register = null,
    ext: enum {
        l, // Release
        a, // Acquire
        ll, // LORelease
        la, // LOAcquire
        u, // Unscaled
        t, // Unprivileged
        g, // Tagged
        @"", // None
    },
    op: enum {
        xp, // Exclusive pair
        r, // Register
        xr, // Exclusive Register
        np, // No-allocate pair
        p, // Pair
    },
    size: enum {
        b, // Byte
        h, // Halfword
        sb, // Signed byte
        sh, // Signed halfword
        sw, // Signed halfword
        @"", // Word or double word
    },
    payload: union(enum) {
        rs: Register,
        imm7: u7,
        simm7: i64,
        imm9: u9,
        simm9: u9,
        imm12: u12,
        shifted_reg: struct {
            rm: Register,
            shift: bool,
            amount: u8,
            shift_type: enum(u3) {
                uxtw = 0b010,
                lsl = 0b011,
                sxtw = 0b110,
                sxtx = 0b111,
            },
        },
    },
    index: ?enum { pre, post } = null,

    pub fn format(self: *const @This(), comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        switch (self.op) {
            .xp, .xr => {
                if (self.payload == .rs) try std.fmt.format(writer, " {},", .{self.payload.rs});
                try std.fmt.format(writer, " {}, ", .{self.rt});
                if (self.rt2) |rt2| try std.fmt.format(writer, "{}, ", .{rt2});
                try std.fmt.format(writer, "[{}]", .{self.rn});
            },
            .r, .p, .np => {
                try std.fmt.format(writer, " {},", .{self.rt});
                if (self.rt2) |rt2| try std.fmt.format(writer, " {},", .{rt2});
                try std.fmt.format(writer, " [{}", .{self.rn});
                if (self.index != null and self.index.? == .post)
                    try std.fmt.format(writer, "]", .{});
                switch (self.payload) {
                    .rs => |reg| try std.fmt.format(writer, ", {}", .{reg}),
                    .imm7 => |imm| if (imm > 0) try std.fmt.format(writer, ", #{}", .{imm}),
                    .simm7 => |imm| if (imm != 0) try std.fmt.format(writer, ", #{}", .{imm}),
                    .imm9 => |imm| if (imm > 0) try std.fmt.format(writer, ", #{}", .{imm}),
                    .simm9 => |simm| if (simm > 0) try std.fmt.format(writer, ", #{}", .{@bitCast(i9, simm)}),
                    .imm12 => |imm| if (imm > 0) try std.fmt.format(writer, ", #{}", .{imm}),
                    .shifted_reg => |sr| {
                        try std.fmt.format(writer, ", {}", .{sr.rm});
                        if (sr.shift or sr.shift_type != .lsl)
                            try std.fmt.format(writer, ", {s}", .{@tagName(sr.shift_type)});
                        if (sr.shift) {
                            try std.fmt.format(writer, " #{}", .{sr.amount});
                        }
                    },
                }
                if (self.index != null and self.index.? == .pre)
                    try std.fmt.format(writer, "]!", .{})
                else if (self.index == null)
                    try std.fmt.format(writer, "]", .{});
            },
        }
    }
};

pub const SysInstr = struct {
    l: bool,
    rt: Register,
    op2: u3,
    crm: u4,
    crn: u4,
    op1: u3,

    pub fn format(self: *const @This(), comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        const sys_op = @as(u14, self.op1) << 11 |
            @as(u14, self.crn) << 7 |
            @as(u14, self.crm) << 3 |
            @as(u14, self.op2);
        if (!self.l and self.crn == 0b0111 and @truncate(u3, self.crm >> 1) == 0b100 and
            (sys_op == 0b00001111000000 or
            sys_op == 0b10001111000000 or
            sys_op == 0b11001111000000 or
            sys_op == 0b00001111000001 or
            sys_op == 0b10001111000001 or
            sys_op == 0b11001111000001 or
            sys_op == 0b00001111000010 or
            sys_op == 0b00001111000011 or
            sys_op == 0b10001111000100 or
            sys_op == 0b10001111000101 or
            sys_op == 0b10001111000110 or
            sys_op == 0b10001111000111))
        {
            const op = if (self.op1 == 0b000 and @truncate(u1, self.crm) == 0b0 and self.op2 == 0b000)
                "s1e1r"
            else if (self.op1 == 0b000 and @truncate(u1, self.crm) == 0b0 and self.op2 == 0b001)
                "s1e1w"
            else if (self.op1 == 0b000 and @truncate(u1, self.crm) == 0b0 and self.op2 == 0b010)
                "s1e0r"
            else if (self.op1 == 0b000 and @truncate(u1, self.crm) == 0b0 and self.op2 == 0b011)
                "s1e0w"
            else if (self.op1 == 0b100 and @truncate(u1, self.crm) == 0b0 and self.op2 == 0b000)
                "s1e2r"
            else if (self.op1 == 0b100 and @truncate(u1, self.crm) == 0b0 and self.op2 == 0b001)
                "s1e2w"
            else if (self.op1 == 0b100 and @truncate(u1, self.crm) == 0b0 and self.op2 == 0b100)
                "s12e1r"
            else if (self.op1 == 0b100 and @truncate(u1, self.crm) == 0b0 and self.op2 == 0b101)
                "s12e1w"
            else if (self.op1 == 0b100 and @truncate(u1, self.crm) == 0b0 and self.op2 == 0b110)
                "s12e0r"
            else if (self.op1 == 0b100 and @truncate(u1, self.crm) == 0b0 and self.op2 == 0b111)
                "s12e0w"
            else if (self.op1 == 0b110 and @truncate(u1, self.crm) == 0b0 and self.op2 == 0b000)
                "s1e3r"
            else if (self.op1 == 0b110 and @truncate(u1, self.crm) == 0b0 and self.op2 == 0b001)
                "s1e3w"
            else if (self.op1 == 0b000 and @truncate(u1, self.crm) == 0b1 and self.op2 == 0b000)
                "s1e1rp"
            else if (self.op1 == 0b000 and @truncate(u1, self.crm) == 0b1 and self.op2 == 0b001)
                "s1e1wp"
            else
                unreachable;
            try std.fmt.format(writer, "at {s}, {}", .{ op, self.rt });
        } else if (!self.l and self.op1 == 0b011 and self.crn == 0b0111 and self.crm == 0b0011 and self.op2 == 0b100)
            try std.fmt.format(writer, "cfp rctx, {}", .{self.rt})
        else if (!self.l and self.op1 == 0b011 and self.crn == 0b0111 and self.crm == 0b0011 and self.op2 == 0b111)
            try std.fmt.format(writer, "cpp rctx, {}", .{self.rt})
        else if (!self.l and self.crn == 0b0111 and
            (sys_op == 0b01101110100001 or
            sys_op == 0b00001110110001 or
            sys_op == 0b00001110110010 or
            sys_op == 0b01101111010001 or
            sys_op == 0b00001111010010 or
            sys_op == 0b01101111011001 or
            sys_op == 0b01101111110001 or
            sys_op == 0b00001111110010 or
            sys_op == 0b01101111101001))
        {
            const op = if (self.op1 == 0b000 and self.crm == 0b0110 and self.op2 == 0b001)
                "ivac"
            else if (self.op1 == 0b000 and self.crm == 0b0110 and self.op2 == 0b010)
                "isw"
            else if (self.op1 == 0b000 and self.crm == 0b1010 and self.op2 == 0b010)
                "csw"
            else if (self.op1 == 0b000 and self.crm == 0b1110 and self.op2 == 0b010)
                "cisw"
            else if (self.op1 == 0b011 and self.crm == 0b0100 and self.op2 == 0b001)
                "zva"
            else if (self.op1 == 0b011 and self.crm == 0b1010 and self.op2 == 0b001)
                "cvac"
            else if (self.op1 == 0b011 and self.crm == 0b1011 and self.op2 == 0b001)
                "cvau"
            else if (self.op1 == 0b011 and self.crm == 0b1110 and self.op2 == 0b001)
                "civac"
            else if (self.op1 == 0b000 and self.crm == 0b0110 and self.op2 == 0b011)
                "igvac"
            else if (self.op1 == 0b000 and self.crm == 0b0110 and self.op2 == 0b100)
                "igsw"
            else if (self.op1 == 0b000 and self.crm == 0b0110 and self.op2 == 0b101)
                "igdvac"
            else if (self.op1 == 0b000 and self.crm == 0b0110 and self.op2 == 0b110)
                "igdsw"
            else if (self.op1 == 0b000 and self.crm == 0b1010 and self.op2 == 0b100)
                "cgsw"
            else if (self.op1 == 0b000 and self.crm == 0b1010 and self.op2 == 0b110)
                "cgdsw"
            else if (self.op1 == 0b000 and self.crm == 0b1110 and self.op2 == 0b100)
                "cigsw"
            else if (self.op1 == 0b000 and self.crm == 0b1110 and self.op2 == 0b110)
                "cigdsw"
            else if (self.op1 == 0b011 and self.crm == 0b0100 and self.op2 == 0b011)
                "gva"
            else if (self.op1 == 0b011 and self.crm == 0b0100 and self.op2 == 0b100)
                "gzva"
            else if (self.op1 == 0b011 and self.crm == 0b1010 and self.op2 == 0b011)
                "cgvac"
            else if (self.op1 == 0b011 and self.crm == 0b1010 and self.op2 == 0b101)
                "cgdvac"
            else if (self.op1 == 0b011 and self.crm == 0b1100 and self.op2 == 0b011)
                "cgvap"
            else if (self.op1 == 0b011 and self.crm == 0b1100 and self.op2 == 0b101)
                "cgdvap"
            else if (self.op1 == 0b011 and self.crm == 0b1101 and self.op2 == 0b011)
                "cgvadp"
            else if (self.op1 == 0b011 and self.crm == 0b1101 and self.op2 == 0b101)
                "cgdvadp"
            else if (self.op1 == 0b011 and self.crm == 0b1110 and self.op2 == 0b011)
                "cigvac"
            else if (self.op1 == 0b011 and self.crm == 0b1110 and self.op2 == 0b101)
                "cigdvac"
            else if (self.op1 == 0b011 and self.crm == 0b1100 and self.op2 == 0b001)
                "cvap"
            else if (self.op1 == 0b011 and self.crm == 0b1101 and self.op2 == 0b001)
                "cvadp"
            else
                unreachable;
            try std.fmt.format(writer, "dc {s}", .{op});
            if (self.rt.toInt() != 0b11111)
                try std.fmt.format(writer, ", {}", .{self.rt});
        } else if (!self.l and self.op1 == 0b011 and self.crn == 0b01111 and self.crm == 0b0011 and self.op2 == 0b101)
            try std.fmt.format(writer, "dvp rctx, {}", .{self.rt})
        else if (self.crn == 0b0111 and
            (sys_op == 0b00001110001000 or
            sys_op == 0b00001110101000 or
            sys_op == 0b01101110101001))
        {
            const op = if (self.op1 == 0b000 and self.crm == 0b0001 and self.op2 == 0b000)
                "ialluis"
            else if (self.op1 == 0b000 and self.crm == 0b0101 and self.op2 == 0b000)
                "iallu"
            else if (self.op1 == 0b011 and self.crm == 0b0101 and self.op2 == 0b001)
                "ivau"
            else
                unreachable;
            try std.fmt.format(writer, "ic {s}", .{op});
            if (self.rt.toInt() != 0b11111)
                try std.fmt.format(writer, ", {}", .{self.rt});
        } else if (self.crn == 0b1000 and
            (sys_op == 0b10010000000001 or
            sys_op == 0b10010000000101 or
            sys_op == 0b00010000011000 or
            sys_op == 0b10010000011000 or
            sys_op == 0b11010000011000 or
            sys_op == 0b00010000011001 or
            sys_op == 0b10010000011001 or
            sys_op == 0b11010000011001 or
            sys_op == 0b00010000011010 or
            sys_op == 0b00010000011011 or
            sys_op == 0b10010000011100 or
            sys_op == 0b00010000011101 or
            sys_op == 0b10010000011101 or
            sys_op == 0b11010000011101 or
            sys_op == 0b10010000011110 or
            sys_op == 0b00010000011111 or
            sys_op == 0b10010000100001 or
            sys_op == 0b10010000100101 or
            sys_op == 0b00010000111000 or
            sys_op == 0b10010000111000 or
            sys_op == 0b11010000111000 or
            sys_op == 0b00010000111001 or
            sys_op == 0b10010000111001 or
            sys_op == 0b11010000111001 or
            sys_op == 0b00010000111010 or
            sys_op == 0b00010000111011 or
            sys_op == 0b10010000111100 or
            sys_op == 0b00010000111101 or
            sys_op == 0b10010000111101 or
            sys_op == 0b11010000111101 or
            sys_op == 0b10010000111110 or
            sys_op == 0b00010000111111))
        {
            const op = switch (@as(u10, self.op1) << 7 | @as(u10, self.crm) << 3 | @as(u10, self.op2)) {
                0b0000001000 => "vmalle1os",
                0b0000001001 => "vae1os",
                0b0000001010 => "aside1os",
                0b0000001011 => "vaae1os",
                0b0000001101 => "vale1os",
                0b0000001111 => "vaale1os",
                0b0000010001 => "rvae1is",
                0b0000010011 => "rvaae1is",
                0b0000010101 => "rvale1is",
                0b0000010111 => "rvaale1is",
                0b0000011000 => "vmalle1is",
                0b0000011001 => "vae1is",
                0b0000011010 => "aside1is",
                0b0000011011 => "vaae1is",
                0b0000011101 => "vale1is",
                0b0000011111 => "vaale1is",
                0b0000101001 => "rvae1os",
                0b0000101011 => "rvaae1os",
                0b0000101101 => "rvale1os",
                0b0000101111 => "rvaale1os",
                0b0000110001 => "rvae1",
                0b0000110011 => "rvaae1",
                0b0000110101 => "rvale1",
                0b0000110111 => "rvaale1",
                0b0000111000 => "vmalle1",
                0b0000111001 => "vae1",
                0b0000111010 => "aside1",
                0b0000111011 => "vaae1",
                0b0000111101 => "vale1",
                0b0000111111 => "vaale1",
                0b1000000001 => "ipas2e1is",
                0b1000000010 => "ripas2e1is",
                0b1000000101 => "ipas2le1is",
                0b1000000110 => "ripas2le1is",
                0b1000001000 => "alle2os",
                0b1000001001 => "vae2os",
                0b1000001100 => "alle1os",
                0b1000001101 => "vale2os",
                0b1000001110 => "vmalls12e1os",
                0b1000010001 => "rvae2is",
                0b1000010101 => "rvale2is",
                0b1000011000 => "alle2is",
                0b1000011001 => "vae2is",
                0b1000011100 => "alle1is",
                0b1000011101 => "vale2is",
                0b1000011110 => "vmalls12e1is",
                0b1000100000 => "ipas2e1os",
                0b1000100001 => "ipas2e1",
                0b1000100010 => "ripas2e1",
                0b1000100011 => "ripas2e1os",
                0b1000100100 => "ipas2le1os",
                0b1000100101 => "ipas2le1",
                0b1000100110 => "ripas2le1",
                0b1000100111 => "ripas2le1os",
                0b1000101001 => "rvae2os",
                0b1000101101 => "rvale2os",
                0b1000110001 => "rvae2",
                0b1000110101 => "rvale2",
                0b1000111000 => "alle2",
                0b1000111001 => "vae2",
                0b1000111100 => "alle1",
                0b1000111101 => "vale2",
                0b1000111110 => "vmalls12e1",
                0b1100001000 => "alle3os",
                0b1100001001 => "vae3os",
                0b1100001101 => "vale3os",
                0b1100010001 => "rvae3is",
                0b1100010101 => "rvale3is",
                0b1100011000 => "alle3is",
                0b1100011001 => "vae3is",
                0b1100011101 => "vale3is",
                0b1100101001 => "rvae3os",
                0b1100101101 => "rvale3os",
                0b1100110001 => "rvae3",
                0b1100110101 => "rvale3",
                0b1100111000 => "alle3",
                0b1100111001 => "vae3",
                0b1100111101 => "vale3",
                else => unreachable,
            };
            try std.fmt.format(writer, "tlbi {s}", .{op});
            if (self.rt.toInt() != 0b11111)
                try std.fmt.format(writer, ", {}", .{self.rt});
        } else {
            try std.fmt.format(writer, "sys", .{});
            if (self.l) {
                try std.fmt.format(writer, "l", .{});
                if (self.rt.toInt() != 0b11111)
                    try std.fmt.format(writer, " {},", .{self.rt});
            }
            try std.fmt.format(writer, " #{}, c{}, c{}, #{}", .{ self.op1, self.crn, self.crm, self.op2 });
            if (!self.l and self.rt.toInt() != 0b11111)
                try std.fmt.format(writer, ", {}", .{self.rt});
        }
    }
};

pub const SysRegMoveInstr = struct {
    rt: Register,
    op2: u3,
    crm: u4,
    crn: u4,
    op1: u3,
    o0: u1,
    o20: u1,

    fn formatSysReg(self: *const @This(), writer: anytype) !void {
        // TODO
        if (false)
            try std.fmt.format(writer, "ACTLR_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "ACTLR_EL2", .{})
        else if (false)
            try std.fmt.format(writer, "ACTLR_EL3", .{})
        else if (false)
            try std.fmt.format(writer, "AFSR0_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "AFSR0_EL2", .{})
        else if (false)
            try std.fmt.format(writer, "AFSR0_EL3", .{})
        else if (false)
            try std.fmt.format(writer, "AFSR1_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "AFSR1_EL2", .{})
        else if (false)
            try std.fmt.format(writer, "AFSR1_EL3", .{})
        else if (false)
            try std.fmt.format(writer, "AIDR_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "AMAIR_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "AMAIR_EL2", .{})
        else if (false)
            try std.fmt.format(writer, "AMAIR_EL3", .{})
        else if (false)
            try std.fmt.format(writer, "CCSIDR_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "CLIDR_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "CPACR_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "CPTR_EL2", .{})
        else if (false)
            try std.fmt.format(writer, "CPTR_EL3", .{})
        else if (false)
            try std.fmt.format(writer, "CPUACTLR_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "CPUACTLR2_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "CPUCFR_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "CPUECTLR_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "CPUPCR_EL3", .{})
        else if (false)
            try std.fmt.format(writer, "CPUPMR_EL3", .{})
        else if (false)
            try std.fmt.format(writer, "CPUPOR_EL3", .{})
        else if (false)
            try std.fmt.format(writer, "CPUPSELR_EL3", .{})
        else if (false)
            try std.fmt.format(writer, "CPUPWRCTLR_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "CSSELR_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "CTR_EL0", .{})
        else if (false)
            try std.fmt.format(writer, "DCZID_EL0", .{})
        else if (false)
            try std.fmt.format(writer, "DISR_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "ERRIDR_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "ERRSELR_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "ERXADDR_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "ERXCTLR_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "ERXFR_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "ERXMISC0_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "ERXMISC1_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "ERXPFGCDNR_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "ERXPFGCTLR_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "ERXPFGFR_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "ERXSTATUS_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "ESR_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "ESR_EL2", .{})
        else if (false)
            try std.fmt.format(writer, "ESR_EL3", .{})
        else if (false)
            try std.fmt.format(writer, "HACR_EL2", .{})
        else if (false)
            try std.fmt.format(writer, "HCR_EL2", .{})
        else if (false)
            try std.fmt.format(writer, "ID_AA64AFR0_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "ID_AA64AFR1_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "ID_AA64DFR0_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "ID_AA64DFR1_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "ID_AA64ISAR0_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "ID_AA64ISAR1_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "ID_AA64MMFR0_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "ID_AA64MMFR1_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "ID_AA64MMFR2_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "ID_AA64PFR0_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "ID_AFR0_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "ID_DFR0_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "ID_ISAR0_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "ID_ISAR1_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "ID_ISAR2_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "ID_ISAR3_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "ID_ISAR4_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "ID_ISAR5_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "ID_ISAR6_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "ID_MMFR0_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "ID_MMFR1_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "ID_MMFR2_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "ID_MMFR3_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "ID_MMFR4_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "ID_PFR0_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "ID_PFR1_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "IFSR32_EL2", .{})
        else if (false)
            try std.fmt.format(writer, "LORC_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "LORID_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "LORN_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "MDCR_EL3", .{})
        else if (false)
            try std.fmt.format(writer, "MIDR_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "MPIDR_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "PAR_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "REVIDR_EL1", .{})
        else if (self.op1 == 0b000 and self.crn == 0b1100 and self.crm == 0b0000 and self.op2 == 0b010)
            try std.fmt.format(writer, "RMR_EL1", .{})
        else if (self.op1 == 0b100 and self.crn == 0b1100 and self.crm == 0b0000 and self.op2 == 0b010)
            try std.fmt.format(writer, "RMR_EL2", .{})
        else if (self.op1 == 0b110 and self.crn == 0b1100 and self.crm == 0b0000 and self.op2 == 0b010)
            try std.fmt.format(writer, "RMR_EL3", .{})
        else if (false)
            try std.fmt.format(writer, "RVBAR_EL3", .{})
        else if (false)
            try std.fmt.format(writer, "SCTLR_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "SCTLR_EL2", .{})
        else if (false)
            try std.fmt.format(writer, "SCTLR_EL3", .{})
        else if (false)
            try std.fmt.format(writer, "TCR_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "TCR_EL2", .{})
        else if (false)
            try std.fmt.format(writer, "TCR_EL3", .{})
        else if (false)
            try std.fmt.format(writer, "TTBR0_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "TTBR0_EL2", .{})
        else if (false)
            try std.fmt.format(writer, "TTBR0_EL3", .{})
        else if (false)
            try std.fmt.format(writer, "TTBR1_EL1", .{})
        else if (false)
            try std.fmt.format(writer, "TTBR1_EL2", .{})
        else if (false)
            try std.fmt.format(writer, "VDISR_EL2", .{})
        else if (false)
            try std.fmt.format(writer, "VSESR_EL2", .{})
        else if (false)
            try std.fmt.format(writer, "VTCR_EL2", .{})
        else if (false)
            try std.fmt.format(writer, "VTTBR_EL2", .{})
        else
            try std.fmt.format(writer, "S{}_{}_C{}_C{}_{}", .{ @as(u8, self.o0) + 2, self.op1, self.crn, self.crm, self.op2 });
    }
};
