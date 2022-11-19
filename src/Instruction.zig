const std = @import("std");
const Register = @import("utils.zig").Register;
const Width = @import("utils.zig").Width;

pub const Condition = enum(u4) {
    eq = 0x0,
    ne,
    hs,
    lo,
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
    nv,
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
    hint: HintInstr,
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
    tstart: SysWithResInstr,
    ttest: SysWithResInstr,
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
    dup: SIMDDataProcInstr,
    // Advanced SIMD scalar pairwise
    fmaxnmp: SIMDDataProcInstr,
    faddp: SIMDDataProcInstr,
    fmaxp: SIMDDataProcInstr,
    fminnmp: SIMDDataProcInstr,
    fminp: SIMDDataProcInstr,
    // Advanced SIMD scalar three different
    sqdmlal,
    sqdmlsl,
    sqdmull,
    // Advanced SIMD scalar three same
    sqadd: SIMDDataProcInstr,
    sqsub: SIMDDataProcInstr,
    sshl: SIMDDataProcInstr,
    sqshl: SIMDDataProcInstr,
    srshl: SIMDDataProcInstr,
    sqrshl: SIMDDataProcInstr,
    cmtst: SIMDDataProcInstr,
    sqmulh: SIMDDataProcInstr,
    sqdmulh: SIMDDataProcInstr,
    fmulh: SIMDDataProcInstr,
    uqadd: SIMDDataProcInstr,
    uqsub: SIMDDataProcInstr,
    cmhi: SIMDDataProcInstr,
    cmhs: SIMDDataProcInstr,
    ushl: SIMDDataProcInstr,
    uqshl: SIMDDataProcInstr,
    uqrshl: SIMDDataProcInstr,
    sqrdmulh: SIMDDataProcInstr,
    vector_fadd: SIMDDataProcInstr,
    vector_fdiv: SIMDDataProcInstr,
    vector_fmaxnm: SIMDDataProcInstr,
    vector_fmax: SIMDDataProcInstr,
    vector_fminnm: SIMDDataProcInstr,
    vector_fmin: SIMDDataProcInstr,
    vector_fmul: SIMDDataProcInstr,
    vector_fsub: SIMDDataProcInstr,
    // Advanced SIMD copy
    smov: SIMDDataProcInstr,
    umov: SIMDDataProcInstr,
    vector_mov: SIMDDataProcInstr,
    ins: SIMDDataProcInstr,
    // Advanced SIMD scalar three same FP16
    fmulx: SIMDDataProcInstr,
    fcmeq: SIMDDataProcInstr,
    frecps: SIMDDataProcInstr,
    frsqrts: SIMDDataProcInstr,
    fcmge: SIMDDataProcInstr,
    facge: SIMDDataProcInstr,
    fabd: SIMDDataProcInstr,
    fcmgt: SIMDDataProcInstr,
    facgt: SIMDDataProcInstr,
    vector_bic: SIMDDataProcInstr,
    fmls: SIMDDataProcInstr,
    vector_orr: SIMDDataProcInstr,
    fmlsl,
    vector_orn: SIMDDataProcInstr,
    uhadd: SIMDDataProcInstr,
    urhadd: SIMDDataProcInstr,
    uhsub: SIMDDataProcInstr,
    urshl: SIMDDataProcInstr,
    umax: SIMDDataProcInstr,
    umin: SIMDDataProcInstr,
    uabd: SIMDDataProcInstr,
    uaba: SIMDDataProcInstr,
    vector_sub: SIMDDataProcInstr,
    mls: SIMDDataProcInstr,
    pmul: SIMDDataProcInstr,
    umaxp: SIMDDataProcInstr,
    uminp: SIMDDataProcInstr,
    vector_eor: SIMDDataProcInstr,
    bsl: SIMDDataProcInstr,
    bit: SIMDDataProcInstr,
    bif: SIMDDataProcInstr,
    // Advanced SIMD two register misc FP16
    // Advanced SIMD three register extension
    // Advanced SIMD two register misc
    rev64: SIMDDataProcInstr,
    saddlp: SIMDDataProcInstr,
    suqadd: SIMDDataProcInstr,
    cnt: SIMDDataProcInstr,
    sadalp: SIMDDataProcInstr,
    vector_cls: SIMDDataProcInstr,
    vector_clz: SIMDDataProcInstr,
    sqabs: SIMDDataProcInstr,
    cmgt: SIMDDataProcInstr,
    cmeq: SIMDDataProcInstr,
    cmlt: SIMDDataProcInstr,
    abs: SIMDDataProcInstr,
    xtn: SIMDDataProcInstr,
    sqxtn: SIMDDataProcInstr,
    fcvtn: SIMDDataProcInstr,
    fcvtl: SIMDDataProcInstr,
    fcmlt: SIMDDataProcInstr,
    vector_frintn: SIMDDataProcInstr,
    vector_frintm: SIMDDataProcInstr,
    vector_scvtf: SIMDDataProcInstr,
    vector_frint32z: SIMDDataProcInstr,
    vector_frint64z: SIMDDataProcInstr,
    vector_ucvtf: SIMDDataProcInstr,
    vector_rev16: SIMDDataProcInstr,
    vector_rev32: SIMDDataProcInstr,
    vector_fabs: SIMDDataProcInstr,
    vector_frintp: SIMDDataProcInstr,
    vector_frintz: SIMDDataProcInstr,
    vector_fcvtas: SIMDDataProcInstr,
    vector_fcvtau: SIMDDataProcInstr,
    vector_fcvtms: SIMDDataProcInstr,
    vector_fcvtmu: SIMDDataProcInstr,
    vector_fcvtns: SIMDDataProcInstr,
    vector_fcvtnu: SIMDDataProcInstr,
    vector_fcvtps: SIMDDataProcInstr,
    vector_fcvtzs: SIMDDataProcInstr,
    vector_fcvtpu: SIMDDataProcInstr,
    vector_rbit: SIMDDataProcInstr,
    vector_fneg: SIMDDataProcInstr,
    vector_frinti: SIMDDataProcInstr,
    vector_fcvtzu: SIMDDataProcInstr,
    vector_fsqrt: SIMDDataProcInstr,
    urecpe: SIMDDataProcInstr,
    frecpe: SIMDDataProcInstr,
    bfcvtn: SIMDDataProcInstr,
    uaddlp: SIMDDataProcInstr,
    usqadd: SIMDDataProcInstr,
    uadalp: SIMDDataProcInstr,
    sqneg: SIMDDataProcInstr,
    cmge: SIMDDataProcInstr,
    cmle: SIMDDataProcInstr,
    neg: SIMDDataProcInstr,
    sqxtun: SIMDDataProcInstr,
    shll: SIMDDataProcInstr,
    uqxtn: SIMDDataProcInstr,
    fcvtxn: SIMDDataProcInstr,
    vector_frinta: SIMDDataProcInstr,
    vector_frintx: SIMDDataProcInstr,
    not: SIMDDataProcInstr,
    fcmle: SIMDDataProcInstr,
    ursqrte: SIMDDataProcInstr,
    frsqrte: SIMDDataProcInstr,
    vector_frint32x: SIMDDataProcInstr,
    vector_frint64x: SIMDDataProcInstr,
    // Advanced SIMD across lanes
    saddlv,
    smaxv,
    sminv,
    addv: SIMDDataProcInstr,
    fmaxnmv,
    fmaxv,
    fminnmv,
    fminv,
    uaddlv,
    umaxv,
    uminv,
    // Advanced SIMD three different
    saddl,
    saddw,
    ssubl,
    ssubw,
    addhn: SIMDDataProcInstr,
    sabal,
    subhn,
    sabdl,
    smlal,
    smlsl,
    smull,
    pmull,
    uaddl,
    uaddw,
    usubl,
    usubw,
    raddhn,
    uabal,
    rsubhn,
    uabdl,
    umlal,
    umlsl,
    umull,
    // Advanced SIMD three same
    vector_add: SIMDDataProcInstr,
    shadd: SIMDDataProcInstr,
    srhadd: SIMDDataProcInstr,
    shsub: SIMDDataProcInstr,
    smax: SIMDDataProcInstr,
    smin: SIMDDataProcInstr,
    sabd: SIMDDataProcInstr,
    saba: SIMDDataProcInstr,
    mla: SIMDDataProcInstr,
    mul: SIMDDataProcInstr,
    smaxp: SIMDDataProcInstr,
    sminp: SIMDDataProcInstr,
    addp: SIMDDataProcInstr,
    vector_and: SIMDDataProcInstr,
    fmla: SIMDDataProcInstr,
    fmlal,
    // Advanced SIMD modified immediate
    // Advanced SIMD shift by immediate
    // Advanced SIMD vector x indexed element
    // Crypto three register, imm2
    // Crypto three register, SHA512
    // Crypto four register
    // XAR
    // Crypto two register SHA512
    // Conversion between floating point and fixed point
    fcvtzu: CvtInstr,
    fcvtzs: CvtInstr,
    ucvtf: CvtInstr,
    scvtf: CvtInstr,
    // Conversion between floating point and integer
    fcvtau: CvtInstr,
    fcvtas: CvtInstr,
    fcvtmu: CvtInstr,
    fcvtms: CvtInstr,
    fcvtpu: CvtInstr,
    fcvtps: CvtInstr,
    fcvtnu: CvtInstr,
    fcvtns: CvtInstr,
    fjcvtzs,
    // Floating point data processing (1 source)
    fmov: FMovInstr,
    fabs: DataProcInstr,
    fneg: DataProcInstr,
    fsqrt: DataProcInstr,
    fcvt: DataProcInstr,
    frintn: DataProcInstr,
    frintp: DataProcInstr,
    frintm: DataProcInstr,
    frintz: DataProcInstr,
    frinta: DataProcInstr,
    frintx: DataProcInstr,
    frinti: DataProcInstr,
    frint32z,
    frint32x,
    frint64z,
    frint64x,
    bfcvt,
    // Floating point compare
    fcmp: FPCompInstr,
    // Floating point immediate
    // Floating point conditional compare
    fccmp: FPCondCompInstr,
    // Floating point data processing (2 source)
    fadd: DataProcInstr,
    fdiv: DataProcInstr,
    fmax: DataProcInstr,
    fmaxnm: DataProcInstr,
    fmin: DataProcInstr,
    fminnm: DataProcInstr,
    fmul: DataProcInstr,
    fnmul: DataProcInstr,
    fsub: DataProcInstr,
    // Floating point conditional select
    fcsel: FPCondSelInstr,
    // Floating point data processing (3 source)
    fmadd: DataProcInstr,
    fmsub: DataProcInstr,
    fnmadd: DataProcInstr,
    fnmsub: DataProcInstr,

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
            .extr => |extr| {
                if (extr.rn.eq(&extr.rm))
                    try std.fmt.format(writer, "ror {}, {}, #{}", .{ extr.rd, extr.rm, extr.imms })
                else
                    try std.fmt.format(writer, "extr {}, {}, {}, #{}", .{ extr.rd, extr.rn, extr.rm, extr.imms });
            },
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
            .fadd,
            .fdiv,
            .fmax,
            .fmaxnm,
            .fmin,
            .fminnm,
            .fmul,
            .fnmul,
            .fsub,
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
            .fabs,
            .fneg,
            .fsqrt,
            .fcvt,
            .frintn,
            .frintp,
            .frintm,
            .frintz,
            .frinta,
            .frintx,
            .frinti,
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
            .fmadd,
            .fmsub,
            .fnmadd,
            .fnmsub,
            => |instr| {
                if (self.* == .smulh or self.* == .umulh)
                    try std.fmt.format(writer, "{s} {}, {}, {}", .{ @tagName(self.*), instr.rd, instr.rn, instr.rm.? })
                else if (self.* == .madd and instr.ra.?.toInt() == 0b11111)
                    try std.fmt.format(writer, "mul {}, {}, {}", .{ instr.rd, instr.rn, instr.rm.? })
                else if (self.* == .smaddl and instr.ra.?.toInt() == 0b11111)
                    try std.fmt.format(writer, "smull {}, {}, {}", .{ instr.rd, instr.rn, instr.rm.? })
                else if (self.* == .umaddl and instr.ra.?.toInt() == 0b11111)
                    try std.fmt.format(writer, "umull {}, {}, {}", .{ instr.rd, instr.rn, instr.rm.? })
                else if (self.* == .msub and instr.ra.?.toInt() == 0b11111)
                    try std.fmt.format(writer, "mneg {}, {}, {}", .{ instr.rd, instr.rn, instr.rm.? })
                else if (self.* == .smsubl and instr.ra.?.toInt() == 0b11111)
                    try std.fmt.format(writer, "smnegl {}, {}, {}", .{ instr.rd, instr.rn, instr.rm.? })
                else if (self.* == .umsubl and instr.ra.?.toInt() == 0b11111)
                    try std.fmt.format(writer, "umnegl {}, {}, {}", .{ instr.rd, instr.rn, instr.rm.? })
                else
                    try std.fmt.format(writer, "{s} {}, {}, {}, {}", .{ @tagName(self.*), instr.rd, instr.rn, instr.rm.?, instr.ra.? });
            },
            .ccmn, .ccmp => |instr| try std.fmt.format(writer, "{s} {}", .{ @tagName(self.*), instr }),
            .csel,
            .csinc,
            .csinv,
            .csneg,
            => |instr| {
                const inverted_cond = @intToEnum(Condition, @enumToInt(instr.cond) ^ 0b1);
                if (self.* == .csinc and instr.rm.toInt() == 0b11111 and instr.rn.toInt() == 0b11111 and @truncate(u3, @enumToInt(instr.cond) >> 1) != 0b111)
                    try std.fmt.format(writer, "cset {}, {s}", .{ instr.rd, @tagName(inverted_cond) })
                else if (self.* == .csinc and instr.rm.toInt() != 0b11111 and instr.rn.toInt() != 0b11111 and instr.rn.eq(&instr.rm) and @truncate(u3, @enumToInt(instr.cond) >> 1) != 0b111)
                    try std.fmt.format(writer, "cinc {}, {}, {s}", .{ instr.rd, instr.rn, @tagName(inverted_cond) })
                else if (self.* == .csinv and instr.rm.toInt() == 0b11111 and instr.rn.toInt() == 0b11111 and @truncate(u3, @enumToInt(instr.cond) >> 1) != 0b111)
                    try std.fmt.format(writer, "csetm {}, {s}", .{ instr.rd, @tagName(inverted_cond) })
                else if (self.* == .csinv and instr.rm.toInt() != 0b11111 and instr.rn.toInt() != 0b11111 and instr.rn.eq(&instr.rm) and @truncate(u3, @enumToInt(instr.cond) >> 1) != 0b111)
                    try std.fmt.format(writer, "cinv {}, {}, {s}", .{ instr.rd, instr.rn, @tagName(inverted_cond) })
                else if (self.* == .csneg and instr.rn.eq(&instr.rm) and @truncate(u3, @enumToInt(instr.cond) >> 1) != 0b111)
                    try std.fmt.format(writer, "cneg {}, {}, {s}", .{ instr.rd, instr.rn, @tagName(inverted_cond) })
                else
                    try std.fmt.format(writer, "{s} {}, {}, {}, {s}", .{
                        @tagName(self.*),
                        instr.rd,
                        instr.rn,
                        instr.rm,
                        @tagName(instr.cond),
                    });
            },
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
            => |instr| try std.fmt.format(writer, "{s} #{}", .{ @tagName(self.*), instr.imm16 }),
            .dcps1,
            .dcps2,
            .dcps3,
            => |instr| {
                try std.fmt.format(writer, "{s}", .{@tagName(self.*)});
                if (instr.imm16 > 0) try std.fmt.format(writer, " #{}", .{instr.imm16});
            },
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
            .ld, .st => |ldst| try std.fmt.format(writer, "{s}{s}{s}{s}{}", .{ @tagName(self.*), if (ldst.ext == .none) "" else @tagName(ldst.ext), @tagName(ldst.op), if (ldst.size == .none) "" else @tagName(ldst.size), ldst }),
            .prfm => |prfm| {
                const rt = prfm.rt.toInt();
                const ty = switch (@truncate(u2, rt >> 3)) {
                    0b00 => "pld",
                    0b01 => "pli",
                    0b10 => "pst",
                    else => null,
                };
                const target = switch (@truncate(u2, rt >> 1)) {
                    0b00 => "l1",
                    0b01 => "l2",
                    0b10 => "l3",
                    else => null,
                };
                const policy = switch (@truncate(u1, rt)) {
                    0 => "keep",
                    1 => "strm",
                };
                try std.fmt.format(writer, "prf{s}m ", .{if (prfm.ext == .none) "" else @tagName(prfm.ext)});
                if (ty != null and target != null)
                    try std.fmt.format(writer, "{?s}{?s}{s}", .{ ty, target, policy })
                else
                    try std.fmt.format(writer, "#{}", .{rt});
                if (prfm.payload == .imm19)
                    try std.fmt.format(writer, ", #{}", .{@bitCast(i21, @as(u21, prfm.payload.imm19) << 2)})
                else {
                    try std.fmt.format(writer, ", [{}", .{prfm.rn});
                    switch (prfm.payload) {
                        .imm12 => |imm| if (imm > 0) try std.fmt.format(writer, ", #{}", .{imm}),
                        .imm19 => |imm| if (imm > 0) try std.fmt.format(writer, ", #{}", .{imm}),
                        .simm9 => |simm| if (simm > 0) try std.fmt.format(writer, ", #{}", .{@bitCast(i9, simm)}),
                        else => {},
                    }
                    try std.fmt.format(writer, "]", .{});
                }
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
            .fcmp => |fcmp| {
                const e = if (fcmp.e) "e" else "";
                try std.fmt.format(writer, "{s}{s} {}, ", .{ @tagName(self.*), e, fcmp.rn });
                switch (fcmp.payload) {
                    .rm => |rm| try std.fmt.format(writer, "{}", .{rm}),
                    .zero => try std.fmt.format(writer, "#0.0", .{}),
                }
            },
            .fccmp => |fccmp| {
                const e = if (fccmp.e) "e" else "";
                try std.fmt.format(writer, "{s}{s} {}, {}, #{}, {s}", .{ @tagName(self.*), e, fccmp.rn, fccmp.rm, fccmp.nzcv, @tagName(fccmp.cond) });
            },
            .fcsel => |fcsel| try std.fmt.format(writer, "{s} {}, {}, {}, {s}", .{ @tagName(self.*), fcsel.rd, fcsel.rn, fcsel.rm, @tagName(fcsel.cond) }),
            .fmov => |fmov| {
                try std.fmt.format(writer, "{s} {}", .{ @tagName(self.*), fmov.rd });
                if (fmov.rd.width == .v)
                    try std.fmt.format(writer, ".d[1]", .{});
                switch (fmov.payload) {
                    .rs => |rs| {
                        try std.fmt.format(writer, ", {}", .{rs});
                        if (rs.width == .v)
                            try std.fmt.format(writer, ".d[1]", .{});
                    },
                    .fp_const => |fp| try std.fmt.format(writer, ", #{d:.8}", .{fp}),
                }
            },
            .fcvtzu,
            .fcvtzs,
            .ucvtf,
            .scvtf,
            .fcvtau,
            .fcvtas,
            .fcvtmu,
            .fcvtms,
            .fcvtpu,
            .fcvtps,
            .fcvtnu,
            .fcvtns,
            => |instr| {
                try std.fmt.format(writer, "{s} {}, {}", .{ @tagName(self.*), instr.rd, instr.rn });
                if (instr.fbits) |fbits|
                    try std.fmt.format(writer, ", #{}", .{64 - @as(u7, fbits)});
            },
            .hint => |instr| try std.fmt.format(writer, "{s} #{}", .{ @tagName(self.*), instr.imm }),
            .vector_add => |instr| try std.fmt.format(writer, "add{}", .{instr}),
            .vector_sub => |instr| try std.fmt.format(writer, "sub{}", .{instr}),
            .vector_mov, .ins => |instr| try std.fmt.format(writer, "mov{}", .{instr}),
            .vector_and => |instr| try std.fmt.format(writer, "and{}", .{instr}),
            .vector_eor => |instr| try std.fmt.format(writer, "eor{}", .{instr}),
            .vector_orn => |instr| try std.fmt.format(writer, "orn{}", .{instr}),
            .vector_orr => |instr| try std.fmt.format(writer, "orr{}", .{instr}),
            .vector_cls => |instr| try std.fmt.format(writer, "cls{}", .{instr}),
            .vector_clz => |instr| try std.fmt.format(writer, "clz{}", .{instr}),
            .vector_bic => |instr| try std.fmt.format(writer, "bic{}", .{instr}),
            .vector_fadd => |instr| try std.fmt.format(writer, "fadd{}", .{instr}),
            .vector_fdiv => |instr| try std.fmt.format(writer, "fdiv{}", .{instr}),
            .vector_fmaxnm => |instr| try std.fmt.format(writer, "fmaxnm{}", .{instr}),
            .vector_fmax => |instr| try std.fmt.format(writer, "fmax{}", .{instr}),
            .vector_fminnm => |instr| try std.fmt.format(writer, "fminnm{}", .{instr}),
            .vector_fmin => |instr| try std.fmt.format(writer, "fmin{}", .{instr}),
            .vector_fmul => |instr| try std.fmt.format(writer, "fmul{}", .{instr}),
            .vector_fsub => |instr| try std.fmt.format(writer, "fsub{}", .{instr}),
            .vector_fabs => |instr| try std.fmt.format(writer, "fabs{}", .{instr}),
            .vector_fcvtas => |instr| try std.fmt.format(writer, "fcvtas{}", .{instr}),
            .vector_fcvtau => |instr| try std.fmt.format(writer, "fcvtau{}", .{instr}),
            .vector_fcvtms => |instr| try std.fmt.format(writer, "fcvtms{}", .{instr}),
            .vector_fcvtmu => |instr| try std.fmt.format(writer, "fcvtmu{}", .{instr}),
            .vector_fcvtns => |instr| try std.fmt.format(writer, "fcvtns{}", .{instr}),
            .vector_fcvtnu => |instr| try std.fmt.format(writer, "fcvtnu{}", .{instr}),
            .vector_fcvtps => |instr| try std.fmt.format(writer, "fcvtps{}", .{instr}),
            .vector_fcvtzs => |instr| try std.fmt.format(writer, "fcvtzs{}", .{instr}),
            .vector_fcvtpu => |instr| try std.fmt.format(writer, "fcvtpu{}", .{instr}),
            .vector_rev16 => |instr| try std.fmt.format(writer, "rev16{}", .{instr}),
            .vector_rev32 => |instr| try std.fmt.format(writer, "rev32{}", .{instr}),
            .vector_frintn => |instr| try std.fmt.format(writer, "frintn{}", .{instr}),
            .vector_frintm => |instr| try std.fmt.format(writer, "frintm{}", .{instr}),
            .vector_frint32z => |instr| try std.fmt.format(writer, "frint32z{}", .{instr}),
            .vector_frint64z => |instr| try std.fmt.format(writer, "frint64z{}", .{instr}),
            .vector_scvtf => |instr| try std.fmt.format(writer, "scvtf{}", .{instr}),
            .vector_frintp => |instr| try std.fmt.format(writer, "frintp{}", .{instr}),
            .vector_frintz => |instr| try std.fmt.format(writer, "frintz{}", .{instr}),
            .vector_frinta => |instr| try std.fmt.format(writer, "frinta{}", .{instr}),
            .vector_frintx => |instr| try std.fmt.format(writer, "frintx{}", .{instr}),
            .vector_frint32x => |instr| try std.fmt.format(writer, "frint32x{}", .{instr}),
            .vector_frint64x => |instr| try std.fmt.format(writer, "frint64x{}", .{instr}),
            .vector_ucvtf => |instr| try std.fmt.format(writer, "ucvtf{}", .{instr}),
            .vector_rbit => |instr| try std.fmt.format(writer, "rbit{}", .{instr}),
            .vector_fneg => |instr| try std.fmt.format(writer, "fneg{}", .{instr}),
            .vector_frinti => |instr| try std.fmt.format(writer, "frinti{}", .{instr}),
            .vector_fcvtzu => |instr| try std.fmt.format(writer, "fcvtzu{}", .{instr}),
            .vector_fsqrt => |instr| try std.fmt.format(writer, "fsqrt{}", .{instr}),
            .not => |instr| try std.fmt.format(writer, "mvn{}", .{instr}),
            .xtn,
            .sqxtn,
            .fcvtn,
            .fcvtl,
            .addhn,
            .bfcvtn,
            .sqxtun,
            .shll,
            .uqxtn,
            => |instr| try std.fmt.format(writer, "{s}{s}{}", .{ @tagName(self.*), if (instr.q != null and instr.q.?) "2" else "", instr }),
            .abs,
            .addp,
            .addv,
            .dup,
            .smov,
            .cmeq,
            .cmge,
            .cmgt,
            .cmhi,
            .cmhs,
            .cmtst,
            .fabd,
            .facge,
            .facgt,
            .faddp,
            .fcmeq,
            .fcmge,
            .fcmgt,
            .fmaxnmp,
            .fmaxp,
            .fminnmp,
            .fminp,
            .fmla,
            .fmls,
            .fmulx,
            .frecps,
            .frsqrts,
            .mla,
            .shadd,
            .srhadd,
            .shsub,
            .smax,
            .smin,
            .sabd,
            .saba,
            .ushl,
            .uqshl,
            .uqrshl,
            .sqrdmulh,
            .sqmulh,
            .sqdmulh,
            .fmulh,
            .uqadd,
            .uqsub,
            .sqadd,
            .sqsub,
            .sshl,
            .sqshl,
            .srshl,
            .sqrshl,
            .mls,
            .mul,
            .pmul,
            .smaxp,
            .sminp,
            .uaba,
            .uhadd,
            .urhadd,
            .uhsub,
            .urshl,
            .umax,
            .umin,
            .uabd,
            .umaxp,
            .uminp,
            .bif,
            .bit,
            .bsl,
            .sadalp,
            .rev64,
            .saddlp,
            .suqadd,
            .cnt,
            .sqabs,
            .cmlt,
            .fcmlt,
            .urecpe,
            .frecpe,
            .uaddlp,
            .usqadd,
            .uadalp,
            .sqneg,
            .fcvtxn,
            .neg,
            .fcmle,
            .ursqrte,
            .frsqrte,
            .cmle,
            => |instr| try std.fmt.format(writer, "{s}{}", .{ @tagName(self.*), instr }),
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
        else if (self.op == .sub and self.rn.reg == 31 and !self.rn.sp)
            try std.fmt.format(writer, "neg{s} {}, ", .{ s, self.rd })
        else if (self.op == .sbc and self.rn.reg == 31 and !self.rn.sp)
            try std.fmt.format(writer, "ngc{s} {}, ", .{ s, self.rd })
        else if (self.op == .add and !self.s and
            (self.rn.reg == 31 or self.rd.reg == 31) and
            self.payload == .imm12 and self.payload.imm12.imm == 0 and self.payload.imm12.sh == 0b0)
        {
            try std.fmt.format(writer, "mov {}, {}", .{ self.rd, self.rn });
            return;
        } else try std.fmt.format(writer, "{s}{s} {}, {}, ", .{
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
            // TODO
            .imm_tag => {},
            .carry => |rm| try std.fmt.format(writer, "{}", .{rm}),
            .shift_reg => |shift| {
                try std.fmt.format(writer, "{s}", .{shift.rm});
                if (shift.imm6 != 0 or shift.shift != 0b00) switch (shift.shift) {
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
                        // TODO
                        std.fmt.bufPrintZ(&m_buf, "{}", .{m_int}) catch unreachable;
                    try std.fmt.format(writer, "{s}{s}", .{ r, m });
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
        } else if (self.op == .orr and !self.s and self.rn.toInt() == 0b11111 and self.payload == .shift_reg and self.payload.shift_reg.shift == 0b00) {
            try std.fmt.format(writer, "mov {}, ", .{self.rd});
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
                if (shift.imm6 != 0 or shift.shift != 0b00) {
                    switch (shift.shift) {
                        0b00 => try std.fmt.format(writer, ", lsl", .{}),
                        0b01 => try std.fmt.format(writer, ", lsr", .{}),
                        0b10 => try std.fmt.format(writer, ", asr", .{}),
                        0b11 => try std.fmt.format(writer, ", ror", .{}),
                    }
                    if (shift.imm6 != 0) try std.fmt.format(writer, " #{}", .{shift.imm6});
                }
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

        const leading_zeroes = @clz(pattern);
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
        if (self.p) imm <<= 12;
        try std.fmt.format(writer, "{}, #{}", .{
            self.rd,
            imm,
        });
    }
};

pub const MovInstr = struct {
    ext: enum(u3) {
        n = 0b00,
        z = 0b10,
        k = 0b11,
        none,
    },
    width: Width,
    hw: u2,
    imm16: u16,
    rd: Register,

    pub fn format(self: *const @This(), comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        try std.fmt.format(writer, "mov{s} {}, #{}", .{ if (self.ext != .none) @tagName(self.ext) else "", self.rd, self.imm16 });
        if (self.width == .w and self.hw != 0)
            try std.fmt.format(writer, ", lsl #16", .{})
        else if (self.width == .x and self.hw != 0)
            try std.fmt.format(writer, ", lsl #{}", .{@intCast(u64, self.hw) * 16});
    }
};

// TODO: redo this
pub const BitfieldInstr = struct {
    opc: u2,
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
            else if ((self.imms == 0b011111 and self.width == .w and self.n == 0) or
                (self.imms == 0b111111 and self.width == .x and self.n == 1))
                "asr"
            else if (self.immr == 0b000000 and self.imms == 0b000111)
                "sxtb"
            else if (self.immr == 0b000000 and self.imms == 0b001111)
                "sxth"
            else if (self.immr == 0b000000 and self.imms == 0b011111)
                "sxtw"
            else
                unreachable,
            .unsigned => if (((self.imms != 0b011111 and self.width == .w and self.n == 0) or
                (self.imms != 0b111111 and self.width == .x and self.n == 1)) and
                @as(u64, self.imms) + 1 == self.immr)
                "lsl"
            else if ((self.imms == 0b011111 and self.width == .w and self.n == 0) or
                (self.imms == 0b111111 and self.width == .x and self.n == 1) and
                ((self.width == .w and self.n == 0) or (self.width == .x and self.n == 1)))
                "lsr"
            else if (self.imms < self.immr)
                "ubfiz"
            else if (self.bfxPreferred())
                "ubfx"
            else if (self.immr == 0b000000 and self.imms == 0b000111)
                "uxtb"
            else if (self.immr == 0b000000 and self.imms == 0b001111)
                "uxth"
            else
                unreachable,
            .none => if (self.imms < self.immr)
                if (self.rn.toInt() == 0b11111)
                    "bfc"
                else
                    "bfi"
            else
                "bfxil",
        };
        if (std.mem.eql(u8, name, "asr") or std.mem.eql(u8, name, "lsr"))
            try std.fmt.format(writer, "{s} {}, {}, #{}", .{ name, self.rd, self.rn, self.immr })
        else if (std.mem.eql(u8, name, "lsl"))
            try std.fmt.format(writer, "{s} {}, {}, #{}", .{ name, self.rd, self.rn, width - self.immr })
        else if (std.mem.eql(u8, name, "sxtb") or std.mem.eql(u8, name, "sxth") or std.mem.eql(u8, name, "sxtw") or
            std.mem.eql(u8, name, "uxtb") or std.mem.eql(u8, name, "uxth") or std.mem.eql(u8, name, "uxtw"))
            try std.fmt.format(writer, "{s} {}, {}", .{ name, self.rd, self.rn })
        else if (std.mem.eql(u8, name, "bfc"))
            try std.fmt.format(writer, "{s} {}, #{}, #{}", .{ name, self.rd, width - self.immr, self.imms + 1 })
        else if (self.imms < self.immr)
            try std.fmt.format(writer, "{s} {}, {}, #{}, #{}", .{ name, self.rd, self.rn, width - self.immr, self.imms + 1 })
        else
            try std.fmt.format(writer, "{s} {}, {}, #{}, #{}", .{ name, self.rd, self.rn, self.immr, (@as(u7, self.imms) + 1) -% self.immr });
    }

    fn bfxPreferred(self: *const @This()) bool {
        const imms = self.imms;
        const immr = self.immr;
        const sf = if (self.width == .x) @as(u8, 1) else 0;
        return !((imms < immr) or
            (imms == sf << 5 | 0b11111) or
            (immr == 0b000000 and ((sf == 0 and (imms == 0b000111 or imms == 0b001111)) or
            (sf << 2 | @truncate(u1, self.opc) == 0b10 and (imms == 0b000111 or imms == 0b001111 or imms == 0b011111)))));
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
    ld_st_prfm: enum { ld, st, prfm },
    rn: Register,
    rt: Register,
    rt2: ?Register = null,
    ext: enum {
        l, // Release
        a, // Acquire
        ll, // LORelease
        la, // LOAcquire
        lu, // Release unscaled
        apu, // Acquire RCpc unscaled
        u, // Unscaled
        t, // Unprivileged
        g, // Tagged
        none, // None
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
        none, // Word or double word
    },
    payload: union(enum) {
        rs: Register,
        imm7: u7,
        simm7: i64,
        imm9: u9,
        simm9: u9,
        imm12: u12,
        imm19: u19,
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
            .xr, .xp => {
                if (self.payload == .rs and self.ld_st_prfm != .ld) try std.fmt.format(writer, " {},", .{self.payload.rs});
                try std.fmt.format(writer, " {}, ", .{self.rt});
                if (self.rt2) |rt2| try std.fmt.format(writer, "{}, ", .{rt2});
                try std.fmt.format(writer, "[{}]", .{self.rn});
            },
            .r, .p, .np => {
                try std.fmt.format(writer, " {},", .{self.rt});
                if (self.payload == .imm19) {
                    try std.fmt.format(writer, " #{}", .{@bitCast(i21, @as(u21, self.payload.imm19) << 2)});
                } else {
                    if (self.rt2 != null and !(self.ext == .l or self.ext == .a)) try std.fmt.format(writer, " {},", .{self.rt2.?});
                    try std.fmt.format(writer, " [{}", .{self.rn});
                    if (self.index != null and self.index.? == .post)
                        try std.fmt.format(writer, "]", .{});
                    if (self.ext != .l and self.ext != .a)
                        switch (self.payload) {
                            .rs => |reg| try std.fmt.format(writer, ", {}", .{reg}),
                            .imm7 => |imm| if (imm != 0) try std.fmt.format(writer, ", #{}", .{imm}),
                            .simm7 => |imm| if (imm != 0) try std.fmt.format(writer, ", #{}", .{imm}),
                            .imm9 => |imm| if (imm != 0) try std.fmt.format(writer, ", #{}", .{imm}),
                            .simm9 => |simm| if (simm != 0) try std.fmt.format(writer, ", #{}", .{@bitCast(i9, simm)}),
                            .imm12 => |imm| if (imm != 0) try std.fmt.format(writer, ", #{}", .{imm}),
                            .shifted_reg => |sr| {
                                try std.fmt.format(writer, ", {}", .{sr.rm});
                                if (sr.shift or sr.shift_type != .lsl)
                                    try std.fmt.format(writer, ", {s}", .{@tagName(sr.shift_type)});
                                if (sr.shift) {
                                    try std.fmt.format(writer, " #{}", .{sr.amount});
                                }
                            },
                            else => unreachable,
                        };
                    if (self.index != null and self.index.? == .pre)
                        try std.fmt.format(writer, "]!", .{})
                    else if (self.index == null)
                        try std.fmt.format(writer, "]", .{});
                }
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
    op: enum { read, write },

    fn formatSysReg(self: *const @This(), writer: anytype) !void {
        // TODO
        if (self.o0 == 0b0 and self.op1 == 0b000 and self.crn == 0b0000 and self.crm == 0b0000 and self.op2 == 0b010)
            try std.fmt.format(writer, "OSDTRRX_EL1", .{})
        else if (self.o0 == 0b0 and self.op1 == 0b010 and self.crn == 0b0000 and self.crm == 0b0000 and self.op2 == 0b000)
            try std.fmt.format(writer, "TEECR32_EL1", .{})
        else if (self.o0 == 0b0 and self.op1 == 0b010 and self.crn == 0b0001 and self.crm == 0b0000 and self.op2 == 0b000)
            try std.fmt.format(writer, "TEEHBR32_EL1", .{})
        else if (self.o0 == 0b0 and self.op1 == 0b011 and self.crn == 0b0000 and self.crm == 0b0001 and self.op2 == 0b000)
            try std.fmt.format(writer, "MDCCSR_EL0", .{})
        else if (self.o0 == 0b0 and self.op1 == 0b000 and self.crn == 0b0000 and self.crm == 0b0010 and self.op2 == 0b000)
            try std.fmt.format(writer, "MDCCINT_EL1", .{})
        else if (self.o0 == 0b0 and self.op1 == 0b000 and self.crn == 0b0000 and self.crm == 0b0010 and self.op2 == 0b010)
            try std.fmt.format(writer, "MDSCR_EL1", .{})
        else if (self.o0 == 0b0 and self.op1 == 0b000 and self.crn == 0b0000 and self.crm == 0b0011 and self.op2 == 0b010)
            try std.fmt.format(writer, "OSDTRTX_EL1", .{})
        else if (self.o0 == 0b0 and self.op1 == 0b011 and self.crn == 0b0000 and self.crm == 0b0100 and self.op2 == 0b000)
            try std.fmt.format(writer, "DBGDTR_EL0", .{})
        else if (self.o0 == 0b0 and self.op1 == 0b011 and self.crn == 0b0000 and self.crm == 0b0101 and self.op2 == 0b000)
            if (self.op == .read)
                try std.fmt.format(writer, "DBGDTRTX_EL0", .{})
            else
                try std.fmt.format(writer, "DBGDTRRX_EL0", .{})
        else if (self.o0 == 0b0 and self.op1 == 0b000 and self.crn == 0b0000 and self.crm == 0b0110 and self.op2 == 0b010)
            try std.fmt.format(writer, "OSECCR_EL1", .{})
        else if (self.o0 == 0b0 and self.op1 == 0b100 and self.crn == 0b0000 and self.crm == 0b0111 and self.op2 == 0b000)
            try std.fmt.format(writer, "DBGVCR32_EL2", .{})
        else if (self.o0 == 0b0 and self.op1 == 0b000 and self.crn == 0b0000 and self.op2 == 0b100)
            try std.fmt.format(writer, "DBGBVR{}_EL1", .{self.crm})
        else if (self.o0 == 0b0 and self.op1 == 0b000 and self.crn == 0b0000 and self.op2 == 0b101)
            try std.fmt.format(writer, "DBGBCR{}_EL1", .{self.crm})
        else if (self.o0 == 0b0 and self.op1 == 0b000 and self.crn == 0b0000 and self.op2 == 0b110)
            try std.fmt.format(writer, "DBGWVR{}_EL1", .{self.crm})
        else if (self.o0 == 0b0 and self.op1 == 0b000 and self.crn == 0b0000 and self.op2 == 0b111)
            try std.fmt.format(writer, "DBGWCR{}_EL1", .{self.crm})
        else if (self.o0 == 0b0 and self.op1 == 0b000 and self.crn == 0b0001 and self.crm == 0b0000 and self.op2 == 0b000)
            try std.fmt.format(writer, "MDRAR_EL1", .{})
        else if (self.o0 == 0b0 and self.op1 == 0b000 and self.crn == 0b0001 and self.crm == 0b0000 and self.op2 == 0b100)
            try std.fmt.format(writer, "OSLAR_EL1", .{})
        else if (self.o0 == 0b0 and self.op1 == 0b000 and self.crn == 0b0001 and self.crm == 0b0001 and self.op2 == 0b100)
            try std.fmt.format(writer, "OSLSR_EL1", .{})
        else if (self.o0 == 0b0 and self.op1 == 0b000 and self.crn == 0b0001 and self.crm == 0b0011 and self.op2 == 0b100)
            try std.fmt.format(writer, "OSDLR_EL1", .{})
        else if (self.o0 == 0b0 and self.op1 == 0b000 and self.crn == 0b0001 and self.crm == 0b0100 and self.op2 == 0b100)
            try std.fmt.format(writer, "DBGPRCR_EL1", .{})
        else if (self.o0 == 0b0 and self.op1 == 0b000 and self.crn == 0b0111 and self.crm == 0b1000 and self.op2 == 0b110)
            try std.fmt.format(writer, "DBGCLAIMSET_EL1", .{})
        else if (self.o0 == 0b0 and self.op1 == 0b000 and self.crn == 0b0111 and self.crm == 0b1001 and self.op2 == 0b110)
            try std.fmt.format(writer, "DBGCLAIMCLR_EL1", .{})
        else if (self.o0 == 0b0 and self.op1 == 0b000 and self.crn == 0b0111 and self.crm == 0b1110 and self.op2 == 0b110)
            try std.fmt.format(writer, "DBGAUTHSTATUS_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0000 and self.crm == 0b0000 and self.op2 == 0b000)
            try std.fmt.format(writer, "MIDR_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b001 and self.crn == 0b0000 and self.crm == 0b0000 and self.op2 == 0b000)
            try std.fmt.format(writer, "CCSIDR_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b001 and self.crn == 0b0000 and self.crm == 0b0000 and self.op2 == 0b010)
            try std.fmt.format(writer, "CCSIDR2_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b010 and self.crn == 0b0000 and self.crm == 0b0000 and self.op2 == 0b000)
            try std.fmt.format(writer, "CSSELR_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b0000 and self.crm == 0b0000 and self.op2 == 0b000)
            try std.fmt.format(writer, "VPIDR_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b001 and self.crn == 0b0000 and self.crm == 0b0000 and self.op2 == 0b001)
            try std.fmt.format(writer, "CLIDR_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b011 and self.crn == 0b0000 and self.crm == 0b0000 and self.op2 == 0b001)
            try std.fmt.format(writer, "CTR_EL0", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0000 and self.crm == 0b0000 and self.op2 == 0b101)
            try std.fmt.format(writer, "MPIDR_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b0000 and self.crm == 0b0000 and self.op2 == 0b101)
            try std.fmt.format(writer, "VMPIDR_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0000 and self.crm == 0b0000 and self.op2 == 0b110)
            try std.fmt.format(writer, "REVIDR_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b001 and self.crn == 0b0000 and self.crm == 0b0000 and self.op2 == 0b111)
            try std.fmt.format(writer, "AIDR_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b011 and self.crn == 0b0000 and self.crm == 0b0000 and self.op2 == 0b111)
            try std.fmt.format(writer, "DCZID_EL0", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0000 and self.crm == 0b0001 and self.op2 == 0b000)
            try std.fmt.format(writer, "ID_PFR0_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0000 and self.crm == 0b0001 and self.op2 == 0b001)
            try std.fmt.format(writer, "ID_PFR1_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0000 and self.crm == 0b0001 and self.op2 == 0b010)
            try std.fmt.format(writer, "ID_DFR0_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0000 and self.crm == 0b0001 and self.op2 == 0b011)
            try std.fmt.format(writer, "ID_AFR0_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0000 and self.crm == 0b0001 and self.op2 == 0b100)
            try std.fmt.format(writer, "ID_MMFR0_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0000 and self.crm == 0b0001 and self.op2 == 0b101)
            try std.fmt.format(writer, "ID_MMFR1_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0000 and self.crm == 0b0001 and self.op2 == 0b110)
            try std.fmt.format(writer, "ID_MMFR2_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0000 and self.crm == 0b0001 and self.op2 == 0b111)
            try std.fmt.format(writer, "ID_MMFR3_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0000 and self.crm == 0b0010 and self.op2 == 0b000)
            try std.fmt.format(writer, "ID_ISAR0_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0000 and self.crm == 0b0010 and self.op2 == 0b001)
            try std.fmt.format(writer, "ID_ISAR1_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0000 and self.crm == 0b0010 and self.op2 == 0b010)
            try std.fmt.format(writer, "ID_ISAR2_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0000 and self.crm == 0b0010 and self.op2 == 0b011)
            try std.fmt.format(writer, "ID_ISAR3_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0000 and self.crm == 0b0010 and self.op2 == 0b100)
            try std.fmt.format(writer, "ID_ISAR4_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0000 and self.crm == 0b0010 and self.op2 == 0b101)
            try std.fmt.format(writer, "ID_ISAR5_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0000 and self.crm == 0b0010 and self.op2 == 0b110)
            try std.fmt.format(writer, "ID_MMFR4_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0000 and self.crm == 0b0011 and self.op2 == 0b110)
            try std.fmt.format(writer, "ID_MMFR5_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0000 and self.crm == 0b0011 and self.op2 == 0b000)
            try std.fmt.format(writer, "MVFR0_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0000 and self.crm == 0b0011 and self.op2 == 0b001)
            try std.fmt.format(writer, "MVFR1_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0000 and self.crm == 0b0011 and self.op2 == 0b010)
            try std.fmt.format(writer, "MVFR2_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0000 and self.crm == 0b0100 and self.op2 == 0b000)
            try std.fmt.format(writer, "ID_AA64PFR0_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0000 and self.crm == 0b0100 and self.op2 == 0b001)
            try std.fmt.format(writer, "ID_AA64PFR1_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0000 and self.crm == 0b0101 and self.op2 == 0b000)
            try std.fmt.format(writer, "ID_AA64DFR0_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0000 and self.crm == 0b0101 and self.op2 == 0b001)
            try std.fmt.format(writer, "ID_AA64DFR1_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0000 and self.crm == 0b0101 and self.op2 == 0b100)
            try std.fmt.format(writer, "ID_AA64AFR0_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0000 and self.crm == 0b0101 and self.op2 == 0b101)
            try std.fmt.format(writer, "ID_AA64AFR1_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0000 and self.crm == 0b0110 and self.op2 == 0b000)
            try std.fmt.format(writer, "ID_AA64ISAR0_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0000 and self.crm == 0b0110 and self.op2 == 0b001)
            try std.fmt.format(writer, "ID_AA64ISAR1_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0000 and self.crm == 0b0110 and self.op2 == 0b010)
            try std.fmt.format(writer, "ID_AA64ISAR2_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0000 and self.crm == 0b0111 and self.op2 == 0b000)
            try std.fmt.format(writer, "ID_AA64MMFR0_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0000 and self.crm == 0b0111 and self.op2 == 0b001)
            try std.fmt.format(writer, "ID_AA64MMFR1_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0000 and self.crm == 0b0111 and self.op2 == 0b010)
            try std.fmt.format(writer, "ID_AA64MMFR2_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0001 and self.crm == 0b0000 and self.op2 == 0b000)
            try std.fmt.format(writer, "SCTLR_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b0001 and self.crm == 0b0000 and self.op2 == 0b000)
            try std.fmt.format(writer, "SCTLR_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b110 and self.crn == 0b0001 and self.crm == 0b0000 and self.op2 == 0b000)
            try std.fmt.format(writer, "SCTLR_EL3", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0001 and self.crm == 0b0000 and self.op2 == 0b001)
            try std.fmt.format(writer, "ACTLR_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b0001 and self.crm == 0b0000 and self.op2 == 0b001)
            try std.fmt.format(writer, "ACTLR_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b110 and self.crn == 0b0001 and self.crm == 0b0000 and self.op2 == 0b001)
            try std.fmt.format(writer, "ACTLR_EL3", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0001 and self.crm == 0b0000 and self.op2 == 0b010)
            try std.fmt.format(writer, "CPACR_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b0001 and self.crm == 0b0001 and self.op2 == 0b000)
            try std.fmt.format(writer, "HCR_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b110 and self.crn == 0b0001 and self.crm == 0b0001 and self.op2 == 0b000)
            try std.fmt.format(writer, "SCR_EL3", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b0001 and self.crm == 0b0001 and self.op2 == 0b001)
            try std.fmt.format(writer, "MDCR_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b110 and self.crn == 0b0001 and self.crm == 0b0001 and self.op2 == 0b001)
            try std.fmt.format(writer, "SDER32_EL3", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b0001 and self.crm == 0b0001 and self.op2 == 0b010)
            try std.fmt.format(writer, "CPTR_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b110 and self.crn == 0b0001 and self.crm == 0b0001 and self.op2 == 0b010)
            try std.fmt.format(writer, "CPTR_EL3", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b0001 and self.crm == 0b0001 and self.op2 == 0b011)
            try std.fmt.format(writer, "HSTR_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b0001 and self.crm == 0b0001 and self.op2 == 0b111)
            try std.fmt.format(writer, "HACR_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b110 and self.crn == 0b0001 and self.crm == 0b0011 and self.op2 == 0b001)
            try std.fmt.format(writer, "MDCR_EL3", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0010 and self.crm == 0b0000 and self.op2 == 0b000)
            try std.fmt.format(writer, "TTBR0_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b0010 and self.crm == 0b0000 and self.op2 == 0b000)
            try std.fmt.format(writer, "TTBR0_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b110 and self.crn == 0b0010 and self.crm == 0b0000 and self.op2 == 0b000)
            try std.fmt.format(writer, "TTBR0_EL3", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0010 and self.crm == 0b0000 and self.op2 == 0b001)
            try std.fmt.format(writer, "TTBR1_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b0010 and self.crm == 0b0000 and self.op2 == 0b001)
            try std.fmt.format(writer, "TTBR1_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0010 and self.crm == 0b0000 and self.op2 == 0b010)
            try std.fmt.format(writer, "TCR_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b0010 and self.crm == 0b0000 and self.op2 == 0b010)
            try std.fmt.format(writer, "TCR_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b110 and self.crn == 0b0010 and self.crm == 0b0000 and self.op2 == 0b010)
            try std.fmt.format(writer, "TCR_EL3", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b0010 and self.crm == 0b0001 and self.op2 == 0b000)
            try std.fmt.format(writer, "VTTBR_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b0010 and self.crm == 0b0001 and self.op2 == 0b010)
            try std.fmt.format(writer, "VTCR_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b0011 and self.crm == 0b0000 and self.op2 == 0b000)
            try std.fmt.format(writer, "DACR32_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0100 and self.crm == 0b0000 and self.op2 == 0b000)
            try std.fmt.format(writer, "SPSR_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b0100 and self.crm == 0b0000 and self.op2 == 0b000)
            try std.fmt.format(writer, "SPSR_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b110 and self.crn == 0b0100 and self.crm == 0b0000 and self.op2 == 0b000)
            try std.fmt.format(writer, "SPSR_EL3", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0100 and self.crm == 0b0000 and self.op2 == 0b001)
            try std.fmt.format(writer, "ELR_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b0100 and self.crm == 0b0000 and self.op2 == 0b001)
            try std.fmt.format(writer, "ELR_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b110 and self.crn == 0b0100 and self.crm == 0b0000 and self.op2 == 0b001)
            try std.fmt.format(writer, "ELR_EL3", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0100 and self.crm == 0b0001 and self.op2 == 0b000)
            try std.fmt.format(writer, "SP_EL0", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b0100 and self.crm == 0b0001 and self.op2 == 0b000)
            try std.fmt.format(writer, "SP_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b110 and self.crn == 0b0100 and self.crm == 0b0001 and self.op2 == 0b000)
            try std.fmt.format(writer, "SP_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0100 and self.crm == 0b0010 and self.op2 == 0b000)
            try std.fmt.format(writer, "SPSel", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b011 and self.crn == 0b0100 and self.crm == 0b0010 and self.op2 == 0b000)
            try std.fmt.format(writer, "NZCV", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b011 and self.crn == 0b0100 and self.crm == 0b0010 and self.op2 == 0b001)
            try std.fmt.format(writer, "DAIF", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0100 and self.crm == 0b0010 and self.op2 == 0b010)
            try std.fmt.format(writer, "CurrentEL", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0100 and self.crm == 0b0010 and self.op2 == 0b011)
            try std.fmt.format(writer, "PAN", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0100 and self.crm == 0b0010 and self.op2 == 0b100)
            try std.fmt.format(writer, "UAO", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b0100 and self.crm == 0b0011 and self.op2 == 0b000)
            try std.fmt.format(writer, "SPSR_irq", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b0100 and self.crm == 0b0011 and self.op2 == 0b001)
            try std.fmt.format(writer, "SPSR_abt", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b0100 and self.crm == 0b0011 and self.op2 == 0b010)
            try std.fmt.format(writer, "SPSR_und", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b0100 and self.crm == 0b0011 and self.op2 == 0b011)
            try std.fmt.format(writer, "SPSR_fiq", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b011 and self.crn == 0b0100 and self.crm == 0b0100 and self.op2 == 0b000)
            try std.fmt.format(writer, "FPCR", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b011 and self.crn == 0b0100 and self.crm == 0b0100 and self.op2 == 0b001)
            try std.fmt.format(writer, "FPSR", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b011 and self.crn == 0b0100 and self.crm == 0b0101 and self.op2 == 0b000)
            try std.fmt.format(writer, "DSPSR_EL0", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b011 and self.crn == 0b0100 and self.crm == 0b0101 and self.op2 == 0b001)
            try std.fmt.format(writer, "DLR_EL0", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0100 and self.crm == 0b0110 and self.op2 == 0b000)
            try std.fmt.format(writer, "ICC_PMR_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0100 and self.crm == 0b0110 and self.op2 == 0b000)
            try std.fmt.format(writer, "ICV_PMR_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b0101 and self.crm == 0b0000 and self.op2 == 0b001)
            try std.fmt.format(writer, "IFSR32_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0101 and self.crm == 0b0001 and self.op2 == 0b000)
            try std.fmt.format(writer, "AFSR0_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b0101 and self.crm == 0b0001 and self.op2 == 0b000)
            try std.fmt.format(writer, "AFSR0_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b110 and self.crn == 0b0101 and self.crm == 0b0001 and self.op2 == 0b000)
            try std.fmt.format(writer, "AFSR0_EL3", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0101 and self.crm == 0b0001 and self.op2 == 0b001)
            try std.fmt.format(writer, "AFSR1_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b0101 and self.crm == 0b0001 and self.op2 == 0b001)
            try std.fmt.format(writer, "AFSR1_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b110 and self.crn == 0b0101 and self.crm == 0b0001 and self.op2 == 0b001)
            try std.fmt.format(writer, "AFSR1_EL3", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0101 and self.crm == 0b0010 and self.op2 == 0b000)
            try std.fmt.format(writer, "ESR_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b0101 and self.crm == 0b0010 and self.op2 == 0b000)
            try std.fmt.format(writer, "ESR_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b110 and self.crn == 0b0101 and self.crm == 0b0010 and self.op2 == 0b000)
            try std.fmt.format(writer, "ESR_EL3", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b0101 and self.crm == 0b0011 and self.op2 == 0b000)
            try std.fmt.format(writer, "FPEXC32_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0110 and self.crm == 0b0000 and self.op2 == 0b000)
            try std.fmt.format(writer, "FAR_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b0110 and self.crm == 0b0000 and self.op2 == 0b000)
            try std.fmt.format(writer, "FAR_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b110 and self.crn == 0b0110 and self.crm == 0b0000 and self.op2 == 0b000)
            try std.fmt.format(writer, "FAR_EL3", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b0110 and self.crm == 0b0000 and self.op2 == 0b100)
            try std.fmt.format(writer, "HPFAR_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b0111 and self.crm == 0b0100 and self.op2 == 0b000)
            try std.fmt.format(writer, "PAR_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b011 and self.crn == 0b1001 and self.crm == 0b1100 and self.op2 == 0b000)
            try std.fmt.format(writer, "PMCR_EL0", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b011 and self.crn == 0b1001 and self.crm == 0b1100 and self.op2 == 0b001)
            try std.fmt.format(writer, "PMCNTENSET_EL0", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b011 and self.crn == 0b1001 and self.crm == 0b1100 and self.op2 == 0b010)
            try std.fmt.format(writer, "PMCNTENCLR_EL0", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b011 and self.crn == 0b1001 and self.crm == 0b1100 and self.op2 == 0b011)
            try std.fmt.format(writer, "PMOVSCLR_EL0", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b011 and self.crn == 0b1001 and self.crm == 0b1100 and self.op2 == 0b100)
            try std.fmt.format(writer, "PMSWINC_EL0", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b011 and self.crn == 0b1001 and self.crm == 0b1100 and self.op2 == 0b101)
            try std.fmt.format(writer, "PMSELR_EL0", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b011 and self.crn == 0b1001 and self.crm == 0b1100 and self.op2 == 0b110)
            try std.fmt.format(writer, "PMCEID0_EL0", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b011 and self.crn == 0b1001 and self.crm == 0b1100 and self.op2 == 0b111)
            try std.fmt.format(writer, "PMCEID1_EL0", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b011 and self.crn == 0b1001 and self.crm == 0b1101 and self.op2 == 0b000)
            try std.fmt.format(writer, "PMCCNTR_EL0", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b011 and self.crn == 0b1001 and self.crm == 0b1101 and self.op2 == 0b001)
            try std.fmt.format(writer, "PMXEVTYPER_EL0", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b011 and self.crn == 0b1001 and self.crm == 0b1101 and self.op2 == 0b010)
            try std.fmt.format(writer, "PMXEVCNTR_EL0", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b011 and self.crn == 0b1001 and self.crm == 0b1110 and self.op2 == 0b000)
            try std.fmt.format(writer, "PMUSERENR_EL0", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1001 and self.crm == 0b1110 and self.op2 == 0b001)
            try std.fmt.format(writer, "PMINTENSET_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1001 and self.crm == 0b1110 and self.op2 == 0b010)
            try std.fmt.format(writer, "PMINTENCLR_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b011 and self.crn == 0b1001 and self.crm == 0b1110 and self.op2 == 0b011)
            try std.fmt.format(writer, "PMOVSSET_EL0", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1010 and self.crm == 0b0010 and self.op2 == 0b000)
            try std.fmt.format(writer, "MAIR_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b1010 and self.crm == 0b0010 and self.op2 == 0b000)
            try std.fmt.format(writer, "MAIR_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b110 and self.crn == 0b1010 and self.crm == 0b0010 and self.op2 == 0b000)
            try std.fmt.format(writer, "MAIR_EL3", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1010 and self.crm == 0b0011 and self.op2 == 0b000)
            try std.fmt.format(writer, "AMAIR_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b1010 and self.crm == 0b0011 and self.op2 == 0b000)
            try std.fmt.format(writer, "AMAIR_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b110 and self.crn == 0b1010 and self.crm == 0b0011 and self.op2 == 0b000)
            try std.fmt.format(writer, "AMAIR_EL3", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1010 and self.crm == 0b0100 and self.op2 == 0b000)
            try std.fmt.format(writer, "LORSA_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1010 and self.crm == 0b0100 and self.op2 == 0b001)
            try std.fmt.format(writer, "LOREA_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1010 and self.crm == 0b0100 and self.op2 == 0b010)
            try std.fmt.format(writer, "LORN_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1010 and self.crm == 0b0100 and self.op2 == 0b011)
            try std.fmt.format(writer, "LORC_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1010 and self.crm == 0b0100 and self.op2 == 0b111)
            try std.fmt.format(writer, "LORID_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1100 and self.crm == 0b0000 and self.op2 == 0b000)
            try std.fmt.format(writer, "VBAR_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b1100 and self.crm == 0b0000 and self.op2 == 0b000)
            try std.fmt.format(writer, "VBAR_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b110 and self.crn == 0b1100 and self.crm == 0b0000 and self.op2 == 0b000)
            try std.fmt.format(writer, "VBAR_EL3", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1100 and self.crm == 0b0000 and self.op2 == 0b001)
            try std.fmt.format(writer, "RVBAR_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b1100 and self.crm == 0b0000 and self.op2 == 0b001)
            try std.fmt.format(writer, "RVBAR_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b110 and self.crn == 0b1100 and self.crm == 0b0000 and self.op2 == 0b001)
            try std.fmt.format(writer, "RVBAR_EL3", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1100 and self.crm == 0b0000 and self.op2 == 0b010)
            try std.fmt.format(writer, "RMR_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b1100 and self.crm == 0b0000 and self.op2 == 0b010)
            try std.fmt.format(writer, "RMR_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b110 and self.crn == 0b1100 and self.crm == 0b0000 and self.op2 == 0b010)
            try std.fmt.format(writer, "RMR_EL3", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1100 and self.crm == 0b0001 and self.op2 == 0b000)
            try std.fmt.format(writer, "ISR_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1100 and self.crm == 0b1000 and self.op2 == 0b000)
            try std.fmt.format(writer, "ICC_IAR0_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1100 and self.crm == 0b1000 and self.op2 == 0b000)
            try std.fmt.format(writer, "ICV_IAR0_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1100 and self.crm == 0b1000 and self.op2 == 0b001)
            try std.fmt.format(writer, "ICC_EOIR0_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1100 and self.crm == 0b1000 and self.op2 == 0b001)
            try std.fmt.format(writer, "ICV_EOIR0_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1100 and self.crm == 0b1000 and self.op2 == 0b010)
            try std.fmt.format(writer, "ICC_HPPIR0_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1100 and self.crm == 0b1000 and self.op2 == 0b010)
            try std.fmt.format(writer, "ICV_HPPIR0_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1100 and self.crm == 0b1000 and self.op2 == 0b011)
            try std.fmt.format(writer, "ICC_BPR0_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1100 and self.crm == 0b1000 and self.op2 == 0b011)
            try std.fmt.format(writer, "ICV_BPR0_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b1100 and self.crm == 0b1000 and self.op2 <= 0b011)
            try std.fmt.format(writer, "ICH_AP0R{}_EL2", .{@truncate(u2, self.op2)})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1100 and self.crm == 0b1000 and self.op2 >= 0b100)
            try std.fmt.format(writer, "ICC_AP0R{}_EL1", .{@truncate(u2, self.op2)})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1100 and self.crm == 0b1000 and self.op2 >= 0b100)
            try std.fmt.format(writer, "ICV_AP0R{}_EL1", .{@truncate(u2, self.op2)})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1100 and self.crm == 0b1001 and self.op2 <= 0b011)
            try std.fmt.format(writer, "ICC_AP1R{}_EL1", .{@truncate(u2, self.op2)})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1100 and self.crm == 0b1001 and self.op2 <= 0b011)
            try std.fmt.format(writer, "ICV_AP1R{}_EL1", .{@truncate(u2, self.op2)})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b1100 and self.crm == 0b1001 and self.op2 <= 0b011)
            try std.fmt.format(writer, "ICH_AP1R{}_EL2", .{@truncate(u2, self.op2)})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b1100 and self.crm == 0b1001 and self.op2 == 0b101)
            try std.fmt.format(writer, "ICC_SRE_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b1100 and self.crm == 0b1011 and self.op2 == 0b000)
            try std.fmt.format(writer, "ICH_HCR_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1100 and self.crm == 0b1011 and self.op2 == 0b001)
            try std.fmt.format(writer, "ICC_DIR_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1100 and self.crm == 0b1011 and self.op2 == 0b001)
            try std.fmt.format(writer, "ICV_DIR_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b1100 and self.crm == 0b1011 and self.op2 == 0b001)
            try std.fmt.format(writer, "ICH_VTR_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b1100 and self.crm == 0b1011 and self.op2 == 0b010)
            try std.fmt.format(writer, "ICH_MISR_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1100 and self.crm == 0b1011 and self.op2 == 0b011)
            try std.fmt.format(writer, "ICC_RPR_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1100 and self.crm == 0b1011 and self.op2 == 0b011)
            try std.fmt.format(writer, "ICV_RPR_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b1100 and self.crm == 0b1011 and self.op2 == 0b011)
            try std.fmt.format(writer, "ICH_EISR_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1100 and self.crm == 0b1011 and self.op2 == 0b101)
            try std.fmt.format(writer, "ICC_SGI1R_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b1100 and self.crm == 0b1011 and self.op2 == 0b101)
            try std.fmt.format(writer, "ICH_ELRSR_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1100 and self.crm == 0b1011 and self.op2 == 0b110)
            try std.fmt.format(writer, "ICC_ASGI1R_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1100 and self.crm == 0b1011 and self.op2 == 0b111)
            try std.fmt.format(writer, "ICC_SGI0R_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b1100 and self.crm == 0b1011 and self.op2 == 0b111)
            try std.fmt.format(writer, "ICH_VMCR_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1100 and self.crm == 0b1100 and self.op2 == 0b000)
            try std.fmt.format(writer, "ICC_IAR1_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1100 and self.crm == 0b1100 and self.op2 == 0b000)
            try std.fmt.format(writer, "ICV_IAR1_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1100 and self.crm == 0b1100 and self.op2 == 0b001)
            try std.fmt.format(writer, "ICC_EOIR1_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1100 and self.crm == 0b1100 and self.op2 == 0b001)
            try std.fmt.format(writer, "ICV_EOIR1_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1100 and self.crm == 0b1100 and self.op2 == 0b010)
            try std.fmt.format(writer, "ICC_HPPIR1_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1100 and self.crm == 0b1100 and self.op2 == 0b010)
            try std.fmt.format(writer, "ICV_HPPIR1_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1100 and self.crm == 0b1100 and self.op2 == 0b011)
            try std.fmt.format(writer, "ICC_BPR1_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1100 and self.crm == 0b1100 and self.op2 == 0b011)
            try std.fmt.format(writer, "ICV_BPR1_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1100 and self.crm == 0b1100 and self.op2 == 0b100)
            try std.fmt.format(writer, "ICC_CTLR_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1100 and self.crm == 0b1100 and self.op2 == 0b100)
            try std.fmt.format(writer, "ICV_CTLR_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b110 and self.crn == 0b1100 and self.crm == 0b1100 and self.op2 == 0b100)
            try std.fmt.format(writer, "ICC_CTLR_EL3", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1100 and self.crm == 0b1100 and self.op2 == 0b101)
            try std.fmt.format(writer, "ICC_SRE_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b110 and self.crn == 0b1100 and self.crm == 0b1100 and self.op2 == 0b101)
            try std.fmt.format(writer, "ICC_SRE_EL3", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1100 and self.crm == 0b1100 and self.op2 == 0b110)
            try std.fmt.format(writer, "ICC_IGRPEN0_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1100 and self.crm == 0b1100 and self.op2 == 0b110)
            try std.fmt.format(writer, "ICV_IGRPEN0_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1100 and self.crm == 0b1100 and self.op2 == 0b111)
            try std.fmt.format(writer, "ICC_IGRPEN1_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1100 and self.crm == 0b1100 and self.op2 == 0b111)
            try std.fmt.format(writer, "ICV_IGRPEN1_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b110 and self.crn == 0b1100 and self.crm == 0b1100 and self.op2 == 0b111)
            try std.fmt.format(writer, "ICC_IGRPEN1_EL3", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b1100 and @truncate(u3, self.crm >> 1) == 0b110)
            try std.fmt.format(writer, "ICH_LR{}_EL2", .{@as(u4, @truncate(u1, self.crm)) << 3 | self.op2})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1101 and self.crm == 0b0000 and self.op2 == 0b001)
            try std.fmt.format(writer, "CONTEXTIDR_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b1101 and self.crm == 0b0000 and self.op2 == 0b001)
            try std.fmt.format(writer, "CONTEXTIDR_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b011 and self.crn == 0b1101 and self.crm == 0b0000 and self.op2 == 0b010)
            try std.fmt.format(writer, "TPIDR_EL0", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b1101 and self.crm == 0b0000 and self.op2 == 0b010)
            try std.fmt.format(writer, "TPIDR_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b110 and self.crn == 0b1101 and self.crm == 0b0000 and self.op2 == 0b010)
            try std.fmt.format(writer, "TPIDR_EL3", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b011 and self.crn == 0b1101 and self.crm == 0b0000 and self.op2 == 0b011)
            try std.fmt.format(writer, "TPIDRRO_EL0", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1101 and self.crm == 0b0000 and self.op2 == 0b100)
            try std.fmt.format(writer, "TPIDR_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b011 and self.crn == 0b1110 and self.crm == 0b0000 and self.op2 == 0b000)
            try std.fmt.format(writer, "CNTFRQ_EL0", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b011 and self.crn == 0b1110 and self.crm == 0b0000 and self.op2 == 0b001)
            try std.fmt.format(writer, "CNTPCT_EL0", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b011 and self.crn == 0b1110 and self.crm == 0b0000 and self.op2 == 0b010)
            try std.fmt.format(writer, "CNTVCT_EL0", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b1110 and self.crm == 0b0000 and self.op2 == 0b011)
            try std.fmt.format(writer, "CNTVOFF_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b000 and self.crn == 0b1110 and self.crm == 0b0001 and self.op2 == 0b000)
            try std.fmt.format(writer, "CNTKCTL_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b1110 and self.crm == 0b0001 and self.op2 == 0b000)
            try std.fmt.format(writer, "CNTHCTL_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b011 and self.crn == 0b1110 and self.crm == 0b0010 and self.op2 == 0b000)
            try std.fmt.format(writer, "CNTP_TVAL_EL0", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b1110 and self.crm == 0b0010 and self.op2 == 0b000)
            try std.fmt.format(writer, "CNTHP_TVAL_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b111 and self.crn == 0b1110 and self.crm == 0b0010 and self.op2 == 0b000)
            try std.fmt.format(writer, "CNTPS_TVAL_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b011 and self.crn == 0b1110 and self.crm == 0b0010 and self.op2 == 0b001)
            try std.fmt.format(writer, "CNTP_CTL_EL0", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b1110 and self.crm == 0b0010 and self.op2 == 0b001)
            try std.fmt.format(writer, "CNTHP_CTL_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b111 and self.crn == 0b1110 and self.crm == 0b0010 and self.op2 == 0b001)
            try std.fmt.format(writer, "CNTPS_CTL_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b011 and self.crn == 0b1110 and self.crm == 0b0010 and self.op2 == 0b010)
            try std.fmt.format(writer, "CNTP_CVAL_EL0", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b1110 and self.crm == 0b0010 and self.op2 == 0b010)
            try std.fmt.format(writer, "CNTHP_CVAL_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b111 and self.crn == 0b1110 and self.crm == 0b0010 and self.op2 == 0b010)
            try std.fmt.format(writer, "CNTPS_CVAL_EL1", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b011 and self.crn == 0b1110 and self.crm == 0b0011 and self.op2 == 0b000)
            try std.fmt.format(writer, "CNTV_TVAL_EL0", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b1110 and self.crm == 0b0011 and self.op2 == 0b000)
            try std.fmt.format(writer, "CNTHV_TVAL_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b011 and self.crn == 0b1110 and self.crm == 0b0011 and self.op2 == 0b001)
            try std.fmt.format(writer, "CNTV_CTL_EL0", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b1110 and self.crm == 0b0011 and self.op2 == 0b001)
            try std.fmt.format(writer, "CNTHV_CTL_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b011 and self.crn == 0b1110 and self.crm == 0b0011 and self.op2 == 0b010)
            try std.fmt.format(writer, "CNTV_CVAL_EL0", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b100 and self.crn == 0b1110 and self.crm == 0b0011 and self.op2 == 0b010)
            try std.fmt.format(writer, "CNTHV_CVAL_EL2", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b011 and self.crn == 0b1110 and @truncate(u2, self.crm >> 2) == 0b10)
            try std.fmt.format(writer, "PMEVCNTR{}_EL0", .{@as(u5, @truncate(u2, self.crm)) << 3 | self.op2})
        else if (self.o0 == 0b1 and self.op1 == 0b011 and self.crn == 0b1110 and self.crm == 0b1111 and self.op2 == 0b111)
            try std.fmt.format(writer, "PMCCFILTR_EL0", .{})
        else if (self.o0 == 0b1 and self.op1 == 0b011 and self.crn == 0b1110 and @truncate(u2, self.crm >> 2) == 0b11)
            try std.fmt.format(writer, "PMEVTYPER{}_EL0", .{@as(u5, @truncate(u2, self.crm)) << 3 | self.op2})
        else
            try std.fmt.format(writer, "S{}_{}_C{}_C{}_{}", .{ @as(u8, self.o0) + 2, self.op1, self.crn, self.crm, self.op2 });
    }
};

pub const FPCompInstr = struct {
    e: bool,
    rn: Register,
    payload: union(enum) { rm: Register, zero },
};

pub const FPCondCompInstr = struct {
    e: bool,
    rn: Register,
    rm: Register,
    nzcv: u4,
    cond: Condition,
};

pub const FPCondSelInstr = struct {
    rn: Register,
    rd: Register,
    rm: Register,
    cond: Condition,
};

pub const SysWithResInstr = struct {
    rt: Register,
};

pub const FMovInstr = struct {
    rd: Register,
    payload: union(enum) {
        rs: Register,
        fp_const: f64,
    },
};

pub const CvtInstr = struct {
    rd: Register,
    rn: Register,
    fbits: ?u6,
};

pub const HintInstr = struct {
    imm: u7,
};

// This is disgusting
pub const SIMDDataProcInstr = struct {
    q: ?bool = null,
    // Yeah we do a little enum abusing
    arrangement: enum(u4) {
        @"8b" = 0b000,
        @"16b" = 0b001,
        @"4h" = 0b010,
        @"8h" = 0b011,
        @"2s" = 0b100,
        @"4s" = 0b101,
        @"2d" = 0b111,
        @"1d" = 0b1000,
        b,
        h,
        s,
        d,
    },
    rm: ?Register = null,
    rn: Register,
    index: ?u4 = null,
    rd: Register,
    post_index: ?u4 = null,
    payload: ?union(enum) {
        shift: u8,
    } = null,

    pub fn format(self: *const @This(), comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        try std.fmt.format(writer, ".{s} {}", .{ @tagName(self.arrangement), self.rd });
        if (self.index) |idx|
            try std.fmt.format(writer, "[{}]", .{idx});
        try std.fmt.format(writer, ", {}", .{self.rn});
        if (self.rm) |rm|
            try std.fmt.format(writer, ", {}", .{rm});
        if (self.post_index) |idx|
            try std.fmt.format(writer, "[{}]", .{idx});
        if (self.payload) |payload| {
            switch (payload) {
                .shift => |shift| try std.fmt.format(writer, ", #{}", .{shift}),
            }
        }
    }
};
