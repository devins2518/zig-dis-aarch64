const std = @import("std");
const Register = @import("utils.zig").Register;
const Width = @import("utils.zig").Width;

pub const Instruction = union(enum) {
    const Self = @This();
    // Branches, Exception generating, and System instructions
    // zig fmt: off
    B: struct {   // Branch
        l: bool,
        imm26: u26,
    },
    BRK,          // Breakpoint Instruction
    CBZ: struct { // Compare and branch
        n: bool,
        width: Width,
        imm19: u19,
        rt: Register,
    },
    TBZ: struct { // Test and branch
        n: bool,
        width: Width,
        b40: u5,
        imm14: u14,
        rt: Register,
    },
    MRS,          // Move System register to general-purpose register
    MSR,          // Move general-purpose register to System register, Move immediate to PE state field
    NOP,          // No operation
    // zig fmt: on

    // Undefined
    UDF: u16,

    // Loads and stores
    LDR, // Load
    STR, // Store
    LDP, // Load pair
    STP, // Store pair
    LDN, // Load N-element structure
    STN, // Store N-element structure
    PRFM, // Prefetch memory
    LDADD,
    LDCLR,
    LDEOR,
    LDSET,
    LDMAX,
    LDMIN,
    STADD,
    STCLR,
    STEOR,
    STSET,
    STMAX,
    STMIN,
    SWP,
    CAS,
    GMI,
    IRG,
    SUBP,
    STG,
    LDG,
    CPY,
    SET,

    // Data processing
    ADD: AddSubInstr,
    SUB: AddSubInstr,
    CMP,
    AND: LogInstr,
    ANDS: LogInstr,
    EOR: LogInstr,
    ORR: LogInstr,
    TST,
    MOV: struct {
        width: Width,
        ext: enum(u2) { n = 0b00, z = 0b10, k = 0b11 },
        imm16: u16,
        rd: Register,
    },
    ADR: struct {
        p: bool,
        immhi: u19,
        immlo: u2,
        rd: Register,
    },
    BFM: struct {
        width: Width,
        tag: enum { signed, none, unsigned },
        immr: u6,
        imms: u6,
        rn: Register,
        rd: Register,
    },
    BFC,
    BFI,
    BFX,
    EXTR: struct {
        width: Width,
        rm: Register,
        imms: u6,
        rn: Register,
        rd: Register,
    },
    ASR,
    LSL,
    LSR,
    ROR,
    SXT,
    NEG,
    ADC,
    SBC,
    NGC,
    BIC,
    EON,

    pub fn fmtPrint(self: *const Self, writer: anytype) !void {
        switch (self.*) {
            .MOV => |mov| try std.fmt.format(writer, "mov{s} {}, #0x{x}", .{ @tagName(mov.ext), mov.rd, mov.imm16 }),

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
    },
};

pub const LogInstr = struct {
    s: bool,
    width: Width,
    rn: Register,
    rd: Register,
    payload: union(enum) {
        imm: struct {
            immr: u6,
            imms: u6,
        },
    },
};
