const std = @import("std");
const Register = @import("utils.zig").Register;
const Width = @import("utils.zig").Width;
const Field = @import("utils.zig").Field;

const AddSubInstr = @import("instruction.zig").AddSubInstr;
const BitfieldInstr = @import("instruction.zig").BitfieldInstr;
const BranchCondInstr = @import("instruction.zig").BranchCondInstr;
const BranchInstr = @import("instruction.zig").BranchInstr;
const CompBranchInstr = @import("instruction.zig").CompBranchInstr;
const ConCompInstr = @import("instruction.zig").ConCompInstr;
const Condition = @import("instruction.zig").Condition;
const DataProcInstr = @import("instruction.zig").DataProcInstr;
const ExceptionInstr = @import("instruction.zig").ExceptionInstr;
const ExtractInstr = @import("instruction.zig").ExtractInstr;
const Instruction = @import("instruction.zig").Instruction;
const LogInstr = @import("instruction.zig").LogInstr;
const MovInstr = @import("instruction.zig").MovInstr;
const PCRelAddrInstr = @import("instruction.zig").PCRelAddrInstr;
const SysWithRegInstr = @import("instruction.zig").SysWithRegInstr;
const TestInstr = @import("instruction.zig").TestInstr;

const Error = error{ EndOfStream, Unallocated, Unimplemented };

pub const Disassembler = struct {
    const Self = @This();

    code: []const u8,
    stream: std.io.FixedBufferStream([]const u8),

    pub fn init(code: []const u8) Self {
        return .{
            .code = code,
            .stream = std.io.fixedBufferStream(code),
        };
    }

    pub fn next(self: *Self) Error!?Instruction {
        const reader = self.stream.reader();

        const op = reader.readIntLittle(u32) catch return null;

        const op0 = op >> 31;
        const op1 = @truncate(u4, op >> 25);

        switch (op1) {
            0b0000 => return try if (op0 == 0) decodeReserve(op) else decodeSME(op), // Reserved and SME
            0b0001 => return error.Unallocated,
            0b0010 => return try decodeSVE(op), // SVE encoding
            0b0011 => return error.Unallocated,
            0b1000, 0b1001 => return try decodeDataProcImm(op), // Data processing - Imm
            0b1010, 0b1011 => return try decodeBranchExcpSysInstr(op), // Branches, exceptions, system instructions
            0b0100, 0b0110, 0b1100, 0b1110 => return error.Unimplemented, // Load/Store
            0b0101, 0b1101 => return try decodeDataProcReg(op), // Data processing - Reg
            0b0111, 0b1111 => return try decodeDataProcScalarFPSIMD(op), // Data processing - Scalar FP and SIMD
        }
    }

    fn decodeReserve(op: u32) Error!Instruction {
        _ = op;
        return error.Unimplemented;
    }

    fn decodeSME(op: u32) Error!Instruction {
        _ = op;
        return error.Unimplemented;
    }

    fn decodeSVE(op: u32) Error!Instruction {
        _ = op;
        return error.Unimplemented;
    }

    fn decodeDataProcImm(op: u32) Error!Instruction {
        const op0 = @truncate(u3, op >> 23);

        return switch (op0) {
            0b000, 0b001 => blk: {
                const p = op >> 31 == 1;
                const payload = PCRelAddrInstr{
                    .p = p,
                    .rd = Register.from(op, .x, false),
                    .immhi = @truncate(u19, op >> 5),
                    .immlo = @truncate(u2, op >> 29),
                };
                break :blk if (p)
                    Instruction{ .adrp = payload }
                else
                    Instruction{ .adr = payload };
            },
            0b010 => blk: {
                const s = @truncate(u1, op >> 29) == 1;
                const op1 = @truncate(u1, op >> 30);
                const width = Width.from(op >> 31);
                const payload = AddSubInstr{
                    .s = s,
                    .op = if (op1 == 0) .add else .sub,
                    .width = width,
                    .rn = Register.from(op >> 5, width, true),
                    .rd = Register.from(op, width, !s),
                    .payload = .{ .imm12 = .{
                        .sh = @truncate(u1, op >> 22),
                        .imm = @truncate(u12, op >> 10),
                    } },
                };
                break :blk if (op1 == 0)
                    Instruction{ .add = payload }
                else
                    Instruction{ .sub = payload };
            },
            0b011 => blk: {
                const o2 = @truncate(u1, op >> 2);
                const sf = @truncate(u1, op >> 31);
                const s = @truncate(u1, op >> 29) == 1;
                const add = @truncate(u1, op >> 30) == 0;
                const payload = AddSubInstr{
                    .s = s,
                    .op = if (add) .add else .sub,
                    .width = .x,
                    .rn = Register.from(op >> 5, .x, s),
                    .rd = Register.from(op, .x, s),
                    .payload = .{ .imm_tag = .{
                        .imm6 = @truncate(u6, op >> 16),
                        .imm4 = @truncate(u4, op >> 10),
                    } },
                };
                break :blk if (o2 == 1 or sf == 0 or (sf == 1 and s))
                    error.Unallocated
                else if (add)
                    Instruction{ .add = payload }
                else
                    Instruction{ .sub = payload };
            },
            0b100 => blk: {
                const width = Width.from(op >> 31);
                const n = @truncate(u1, op >> 22);
                const opc = @truncate(u2, op >> 29);
                const payload = LogInstr{
                    .s = opc == 0b11,
                    .n = @truncate(u1, op >> 22),
                    .width = width,
                    .rn = Register.from(op >> 5, width, true),
                    .rd = Register.from(op, width, true),
                    .payload = .{ .imm = .{
                        .immr = @truncate(u6, op >> 16),
                        .imms = @truncate(u6, op >> 10),
                    } },
                };
                break :blk if (width == .w and n == 1) error.Unallocated else switch (opc) {
                    0b00, 0b11 => Instruction{ .@"and" = payload },
                    0b01 => Instruction{ .orr = payload },
                    0b10 => Instruction{ .eor = payload },
                };
            },
            0b101 => blk: {
                const width = Width.from(op >> 31);
                const opc = @truncate(u2, op >> 29);
                const hw = @truncate(u2, op >> 21);
                break :blk if (opc == 0b01 or (width == .w and (hw == 0b10 or hw == 0b11)))
                    error.Unallocated
                else .{ .mov = .{
                    .ext = @intToEnum(Field(MovInstr, .ext), opc),
                    .width = width,
                    .hw = @truncate(u2, op >> 21),
                    .imm16 = @truncate(u16, op >> 5),
                    .rd = Register.from(op, width, false),
                } };
            },
            0b110 => blk: {
                const opc = @truncate(u2, op >> 29);
                const n = @truncate(u1, op >> 22);
                const width = Width.from(op >> 31);
                break :blk if (opc == 0b11 or (width == .w and n == 0b1))
                    error.Unallocated
                else
                    Instruction{ .bfm = BitfieldInstr{
                        .n = n,
                        .width = width,
                        .ext = @intToEnum(Field(BitfieldInstr, .ext), opc),
                        .immr = @truncate(u6, op >> 16),
                        .imms = @truncate(u6, op >> 10),
                        .rn = Register.from(op >> 5, width, false),
                        .rd = Register.from(op, width, false),
                    } };
            },
            0b111 => blk: {
                const width = Width.from(op >> 31);
                const op21 = @truncate(u2, op >> 29);
                const n = @truncate(u1, op >> 22);
                const o0 = @truncate(u1, op >> 21);
                const imms = @truncate(u6, op >> 10);
                break :blk if (op21 != 0b00 or
                    (op21 == 0b00 and o0 == 1) or
                    (@enumToInt(width) == 0 and imms >= 0b100000) or
                    (@enumToInt(width) == 0 and n == 1) or
                    (@enumToInt(width) == 1 and n == 0))
                    error.Unallocated
                else
                    Instruction{ .extr = ExtractInstr{
                        .rm = Register.from(op >> 16, width, false),
                        .imms = imms,
                        .rn = Register.from(op >> 5, width, false),
                        .rd = Register.from(op, width, false),
                    } };
            },
        };
    }

    fn decodeBranchExcpSysInstr(op: u32) Error!Instruction {
        const op0 = @truncate(u3, op >> 29);
        const op1 = @truncate(u14, op >> 12);
        const op2 = @truncate(u5, op);

        if (op0 == 0b010 and op1 <= 0b01111111111111) {
            const o0 = @truncate(u1, op >> 4);
            const o1 = @truncate(u1, op >> 24);
            const payload = BranchCondInstr{
                .imm19 = @truncate(u19, op >> 5),
                .cond = @intToEnum(Condition, @truncate(u4, op)),
            };
            return if (o0 == 0b0 and o1 == 0b0)
                Instruction{ .bcond = payload }
            else if (o0 == 0b1 and o1 == 0b0)
                Instruction{ .bccond = payload }
            else
                error.Unallocated;
        } else if (op0 == 0b110 and op1 <= 0b00111111111111) {
            const opc = @truncate(u3, op >> 21);
            const opc2 = @truncate(u3, op >> 2);
            const ll = @truncate(u2, op);
            const payload = ExceptionInstr{ .imm16 = @truncate(u16, op >> 5) };
            return if (opc == 0b000 and opc2 == 0b000 and ll == 0b01)
                Instruction{ .svc = payload }
            else if (opc == 0b000 and opc2 == 0b000 and ll == 0b10)
                Instruction{ .hvc = payload }
            else if (opc == 0b000 and opc2 == 0b000 and ll == 0b11)
                Instruction{ .smc = payload }
            else if (opc == 0b001 and opc2 == 0b000 and ll == 0b00)
                Instruction{ .brk = payload }
            else if (opc == 0b010 and opc2 == 0b000 and ll == 0b00)
                Instruction{ .hlt = payload }
            else if (opc == 0b011 and opc2 == 0b000 and ll == 0b00)
                Instruction{ .tcancel = payload }
            else if (opc == 0b101 and opc2 == 0b000 and ll == 0b01)
                Instruction{ .dcps1 = payload }
            else if (opc == 0b101 and opc2 == 0b000 and ll == 0b10)
                Instruction{ .dcps2 = payload }
            else if (opc == 0b101 and opc2 == 0b000 and ll == 0b11)
                Instruction{ .dcps3 = payload }
            else
                error.Unallocated;
        } else if (op0 == 0b110 and op1 == 0b01000000110001) {
            const crm = @truncate(u4, op >> 8);
            const o2 = @truncate(u3, op >> 5);
            const payload = SysWithRegInstr{
                .rd = Register.from(op, .x, false),
            };
            return if (crm == 0b0000 and o2 == 0b000)
                Instruction{ .wfet = payload }
            else if (crm == 0b0000 and o2 == 0b001)
                Instruction{ .wfit = payload }
            else
                error.Unallocated;
        } else if (op0 == 0b110 and op1 == 0b01000000110010 and op2 == 0b11111) {
            const crm = @truncate(u4, op >> 8);
            const o2 = @truncate(u3, op >> 5);
            return if (crm == 0b0000 and o2 == 0b000)
                @as(Instruction, Instruction.nop)
            else if (crm == 0b0000 and o2 == 0b001)
                @as(Instruction, Instruction.yield)
            else if (crm == 0b0000 and o2 == 0b010)
                @as(Instruction, Instruction.wfe)
            else if (crm == 0b0000 and o2 == 0b011)
                @as(Instruction, Instruction.wfi)
            else if (crm == 0b0000 and o2 == 0b100)
                @as(Instruction, Instruction.sev)
            else if (crm == 0b0000 and o2 == 0b101)
                @as(Instruction, Instruction.sevl)
            else if (crm == 0b0000 and o2 == 0b110)
                @as(Instruction, Instruction.dgh)
            else if (crm == 0b0000 and o2 == 0b111)
                @as(Instruction, Instruction.xpac)
            else if (crm == 0b0001 and o2 == 0b000)
                @as(Instruction, Instruction.pacia1716)
            else if (crm == 0b0001 and o2 == 0b010)
                @as(Instruction, Instruction.pacib1716)
            else if (crm == 0b0001 and o2 == 0b100)
                @as(Instruction, Instruction.autia1716)
            else if (crm == 0b0001 and o2 == 0b110)
                @as(Instruction, Instruction.autib1716)
            else if (crm == 0b0010 and o2 == 0b000)
                @as(Instruction, Instruction.esb)
            else if (crm == 0b0010 and o2 == 0b001)
                @as(Instruction, Instruction.psb_csync)
            else if (crm == 0b0010 and o2 == 0b010)
                @as(Instruction, Instruction.tsb_csync)
            else if (crm == 0b0010 and o2 == 0b100)
                @as(Instruction, Instruction.csdb)
            else if (crm == 0b0011 and o2 == 0b000)
                @as(Instruction, Instruction.paciaz)
            else if (crm == 0b0011 and o2 == 0b001)
                @as(Instruction, Instruction.paciasp)
            else if (crm == 0b0011 and o2 == 0b010)
                @as(Instruction, Instruction.pacibz)
            else if (crm == 0b0011 and o2 == 0b011)
                @as(Instruction, Instruction.pacibsp)
            else if (crm == 0b0011 and o2 == 0b100)
                @as(Instruction, Instruction.autiaz)
            else if (crm == 0b0011 and o2 == 0b101)
                @as(Instruction, Instruction.autiasp)
            else if (crm == 0b0011 and o2 == 0b110)
                @as(Instruction, Instruction.autibz)
            else if (crm == 0b0011 and o2 == 0b111)
                @as(Instruction, Instruction.autibsp)
            else if (crm == 0b0100 and @truncate(u1, o2) == 0b0)
                @as(Instruction, Instruction.bti)
            else
                @as(Instruction, Instruction.hint);
        } else if (op0 == 0b110 and op1 == 0b01000000110011) {
            @panic("barriers");
        } else if (op0 == 0b110 and @truncate(u7, op1 >> 7) == 0b0100000 and @truncate(u4, op1) == 0b0100) {
            @panic("pstate");
        } else if (op0 == 0b110 and @truncate(u7, op1 >> 7) == 0b0100100) {
            @panic("system with results");
        } else if (op0 == 0b110 and (@truncate(u7, op1 >> 7) == 0b0100001 or @truncate(u7, op1 >> 7) == 0b0100101)) {
            @panic("system instructions");
        } else if (op0 == 0b110 and (@truncate(u6, op1 >> 8) == 0b010001 or @truncate(u6, op1 >> 8) == 0b010011)) {
            @panic("system register");
        } else if (op0 == 0b110 and op1 >= 0b10000000000000) {
            const opc = @truncate(u4, op >> 21);
            const o2 = @truncate(u5, op >> 16);
            const o3 = @truncate(u6, op >> 10);
            const o4 = @truncate(u5, op);
            const rn = Register.from(op >> 5, .x, false);
            const payload = BranchInstr{ .reg = rn };
            return if (opc == 0b0000 and o2 == 0b11111 and o3 == 0b000000 and o4 == 0b00000)
                Instruction{ .br = payload }
            else if (opc == 0b0001 and o2 == 0b11111 and o3 == 0b000000 and o4 == 0b00000)
                Instruction{ .blr = payload }
            else if (opc == 0b0010 and o2 == 0b11111 and o3 == 0b000000 and o4 == 0b00000)
                Instruction{ .ret = payload }
            else if (opc == 0b0100 and o2 == 0b11111 and
                o3 == 0b000000 and o4 == 0b00000 and rn.toInt() == 0b11111)
                @as(Instruction, Instruction.eret) // TODO: stage1 moment
            else if (opc == 0b0101 and o2 == 0b11111 and
                o3 == 0b000000 and o4 == 0b00000 and rn.toInt() == 0b11111)
                @as(Instruction, Instruction.drps) // TODO: stage1 moment
            else
                error.Unimplemented; // Pauth
        } else if (op0 == 0b000 or op0 == 0b100) {
            const o = @truncate(u1, op >> 31);
            const payload = BranchInstr{ .imm = @truncate(u26, op) };
            return if (o == 0)
                Instruction{ .b = payload }
            else
                Instruction{ .bl = payload };
        } else if ((op0 == 0b001 or op0 == 0b101) and op1 <= 0b01111111111111) {
            const width = Width.from(op >> 31);
            const neg = @truncate(u1, op >> 24) == 1;
            const payload = CompBranchInstr{
                .imm19 = @truncate(u19, op >> 5),
                .rt = Register.from(op, width, false),
            };
            return if (neg)
                Instruction{ .cbnz = payload }
            else
                Instruction{ .cbz = payload };
        } else if ((op0 == 0b001 or op0 == 0b101) and op1 >= 0b10000000000000) {
            const o = @truncate(u1, op >> 24);
            const payload = TestInstr{
                .b5 = @truncate(u1, op >> 31),
                .b40 = @truncate(u5, op >> 19),
                .imm14 = @truncate(u14, op >> 5),
                .rt = Register.from(op, .x, false),
            };
            return if (o == 0)
                Instruction{ .tbz = payload }
            else
                Instruction{ .tbnz = payload };
        } else return error.Unallocated;
    }

    fn decodeDataProcReg(op: u32) Error!Instruction {
        const op0 = @truncate(u1, op >> 30);
        const op1 = @truncate(u1, op >> 28);
        const op2 = @truncate(u4, op >> 21);
        const op3 = @truncate(u6, op >> 10);
        _ = op0;

        // TODO: refactor to use return on top if (fixed in stage2)
        // https://github.com/ziglang/zig/issues/10601
        if (op1 == 0) return switch (op2) {
            0b0000...0b0111 => blk: { // logical shifted reg
                const imm6 = @truncate(u6, op >> 10);
                const opc = @truncate(u2, op >> 29);
                const width = Width.from(op >> 31);
                const n = @truncate(u1, op >> 21);
                const payload = LogInstr{
                    .s = opc == 0b11,
                    .n = @truncate(u1, op >> 21),
                    .width = width,
                    // TODO: check sp
                    .rn = Register.from(op >> 5, width, false),
                    .rd = Register.from(op, width, false),
                    .payload = .{ .shift_reg = .{
                        .rm = Register.from(op >> 16, width, false),
                        .imm6 = imm6,
                    } },
                };
                break :blk if (width == .w and imm6 >= 0b100000)
                    error.Unallocated
                else switch (@as(u3, opc) << 2 | n) {
                    0b000, 0b110 => Instruction{ .@"and" = payload },
                    0b001, 0b111 => Instruction{ .bic = payload },
                    0b010 => Instruction{ .orr = payload },
                    0b011 => Instruction{ .orn = payload },
                    0b100 => Instruction{ .eor = payload },
                    0b101 => Instruction{ .eon = payload },
                };
            },

            0b1000, 0b1010, 0b1100, 0b1110 => blk: { // add/sub shifted reg
                const width = Width.from(op >> 31);
                const s = @truncate(u1, op >> 29) == 1;
                const add = @truncate(u1, op >> 30) == 0;
                const payload = AddSubInstr{
                    .s = s,
                    .op = if (add) .add else .sub,
                    .width = width,
                    .rn = Register.from(op >> 5, width, false),
                    .rd = Register.from(op, width, false),
                    .payload = .{ .shift_reg = .{
                        .rm = Register.from(op >> 16, width, false),
                        .imm6 = @truncate(u6, op >> 10),
                        .shift = @truncate(u2, op >> 22),
                    } },
                };
                break :blk if (add)
                    Instruction{ .add = payload }
                else
                    Instruction{ .sub = payload };
            },

            0b1001, 0b1011, 0b1101, 0b1111 => blk: { // add/sub extended reg
                const width = Width.from(op >> 31);
                const s = @truncate(u1, op >> 29) == 1;
                const add = @truncate(u1, op >> 30) == 0;
                const opt = @truncate(u2, op >> 22);
                const imm3 = @truncate(u3, op >> 10);
                const payload = AddSubInstr{
                    .s = s,
                    .op = if (add) .add else .sub,
                    .width = width,
                    .rn = Register.from(op >> 5, width, true),
                    .rd = Register.from(op, width, !s),
                    .payload = .{ .ext_reg = .{
                        .rm = Register.from(op >> 16, width, false),
                        .option = @truncate(u3, op >> 13),
                        .imm3 = imm3,
                    } },
                };
                break :blk if (imm3 > 0b100 or opt != 0b00)
                    error.Unallocated
                else if (add)
                    Instruction{ .add = payload }
                else
                    Instruction{ .sub = payload };
            },
        } else return switch (op2) {
            0b0000 => switch (op3) {
                0b000000 => {
                    const adc = @truncate(u1, op >> 30) == 0;
                    const width = Width.from(op >> 31);
                    const payload = AddSubInstr{
                        .s = @truncate(u1, op >> 29) == 1,
                        .op = if (adc) .adc else .sbc,
                        .width = width,
                        .rn = Register.from(op >> 5, width, false),
                        .rd = Register.from(op, width, false),
                        .payload = .{ .carry = Register.from(op >> 16, width, false) },
                    };
                    return if (adc)
                        Instruction{ .adc = payload }
                    else
                        Instruction{ .sbc = payload };
                },
                0b000001, 0b100001 => error.Unimplemented, // rotr into flags
                0b000010, 0b010010, 0b100010, 0b110010 => error.Unimplemented, // eval into flags
                else => error.Unallocated,
            },

            0b0010 => { // cond compare
                const reg = @truncate(u1, op >> 11) == 0;
                const width = Width.from(op >> 31);
                const o3 = @truncate(u1, op >> 4);
                const o2 = @truncate(u1, op >> 10);
                const s = @truncate(u1, op >> 29);
                const cmn = @truncate(u1, op >> 30) == 0;
                const payload = ConCompInstr{
                    .cond = @intToEnum(Condition, @truncate(u4, op >> 12)),
                    .rn = Register.from(op >> 5, width, false),
                    .nzcv = @truncate(u4, op),
                    .payload = if (reg) .{
                        .rm = Register.from(op >> 16, width, false),
                    } else .{ .imm5 = @truncate(u5, op >> 16) },
                };
                return if (o3 == 1 or o2 == 1 or s == 0)
                    error.Unallocated
                else if (cmn)
                    Instruction{ .ccmn = payload }
                else
                    Instruction{ .ccmp = payload };
            },

            0b0100 => { // condselect
                const width = Width.from(op >> 31);
                const s = @truncate(u1, op >> 29);
                const o = @truncate(u1, op >> 30);
                const o2 = @truncate(u2, op >> 10);
                const payload = .{
                    .rm = Register.from(op >> 16, width, false),
                    .cond = @intToEnum(Condition, @truncate(u4, op >> 12)),
                    .rn = Register.from(op >> 5, width, false),
                    .rd = Register.from(op, width, false),
                };
                return if (s == 1 or o2 > 0b01)
                    error.Unallocated
                else if (o == 0 and o2 == 0b00)
                    Instruction{ .csel = payload }
                else if (o == 0 and o2 == 0b01)
                    Instruction{ .csinc = payload }
                else if (o == 1 and o2 == 0b00)
                    Instruction{ .csinv = payload }
                else if (o == 1 and o2 == 0b01)
                    Instruction{ .csneg = payload }
                else
                    error.Unallocated;
            },

            0b0110 => { // data processing 1/2 source
                const width = Width.from(op >> 31);
                const one_source = @truncate(u1, op >> 30) == 1;
                const opcode = @truncate(u6, op >> 10);
                const s = @truncate(u1, op >> 29);
                const payload = DataProcInstr{
                    // TODO: check for sp
                    .rm = if (!one_source) Register.from(op >> 16, width, false) else null,
                    .rn = Register.from(op >> 5, width, false),
                    .rd = Register.from(op, width, false),
                };
                return if (one_source) blk: {
                    const opcode2 = @truncate(u5, op >> 16);
                    const rn = @truncate(u5, op >> 5);
                    break :blk if (s == 1)
                        error.Unallocated
                    else if (opcode == 0b000000 and opcode2 == 0b00000)
                        Instruction{ .rbit = payload }
                    else if (opcode == 0b000001 and opcode2 == 0b00000)
                        Instruction{ .rev16 = payload }
                    else if (((opcode == 0b000010 and width == .w) or (opcode == 0b000011 and width == .x)) and opcode2 == 0b00000)
                        Instruction{ .rev = payload }
                    else if (opcode == 0b000100 and opcode2 == 0b00000)
                        Instruction{ .clz = payload }
                    else if (opcode == 0b000101 and opcode2 == 0b00000)
                        Instruction{ .cls = payload }
                    else if (width == .x and opcode == 0b000010 and opcode2 == 0b00000)
                        Instruction{ .rev32 = payload }
                    else if (width == .x and opcode == 0b000000 and opcode2 == 0b00001)
                        @panic("pacia")
                    else if (width == .x and opcode == 0b000001 and opcode2 == 0b00001)
                        @panic("pacib")
                    else if (width == .x and opcode == 0b000010 and opcode2 == 0b00001)
                        @panic("pacda")
                    else if (width == .x and opcode == 0b000011 and opcode2 == 0b00001)
                        @panic("pacdb")
                    else if (width == .x and opcode == 0b000100 and opcode2 == 0b00001)
                        @panic("autia")
                    else if (width == .x and opcode == 0b000101 and opcode2 == 0b00001)
                        @panic("autib")
                    else if (width == .x and opcode == 0b000110 and opcode2 == 0b00001)
                        @panic("autda")
                    else if (width == .x and opcode == 0b000111 and opcode2 == 0b00001)
                        @panic("autdb")
                    else if (width == .x and opcode == 0b001000 and opcode2 == 0b00001 and rn == 0b11111)
                        @panic("paciza")
                    else if (width == .x and opcode == 0b001001 and opcode2 == 0b00001 and rn == 0b11111)
                        @panic("pacizb")
                    else if (width == .x and opcode == 0b001001 and opcode2 == 0b00001 and rn == 0b11111)
                        @panic("pacizb")
                    else if (width == .x and opcode == 0b001010 and opcode2 == 0b00001 and rn == 0b11111)
                        @panic("pacdza")
                    else if (width == .x and opcode == 0b001011 and opcode2 == 0b00001 and rn == 0b11111)
                        @panic("pacdzb")
                    else if (width == .x and opcode == 0b001100 and opcode2 == 0b00001 and rn == 0b11111)
                        @panic("autiza")
                    else if (width == .x and opcode == 0b001101 and opcode2 == 0b00001 and rn == 0b11111)
                        @panic("autizb")
                    else if (width == .x and opcode == 0b001110 and opcode2 == 0b00001 and rn == 0b11111)
                        @panic("autiza")
                    else if (width == .x and opcode == 0b001111 and opcode2 == 0b00001 and rn == 0b11111)
                        @panic("autizb")
                    else if (width == .x and opcode == 0b010000 and opcode2 == 0b00001 and rn == 0b11111)
                        @panic("xpaci")
                    else if (width == .x and opcode == 0b010001 and opcode2 == 0b00001 and rn == 0b11111)
                        @panic("xpacd")
                    else
                        error.Unallocated;
                } else if (s == 0 and opcode == 0b000010)
                    Instruction{ .udiv = payload }
                else if (s == 0 and opcode == 0b000011)
                    Instruction{ .sdiv = payload }
                else if (s == 0 and opcode == 0b001000)
                    Instruction{ .lslv = payload }
                else if (s == 0 and opcode == 0b001001)
                    Instruction{ .lsrv = payload }
                else if (s == 0 and opcode == 0b001010)
                    Instruction{ .asrv = payload }
                else if (s == 0 and opcode == 0b001011)
                    Instruction{ .rorv = payload }
                else if (width == .w and s == 0 and opcode == 0b010000)
                    Instruction{ .crc32b = payload }
                else if (width == .w and s == 0 and opcode == 0b010001)
                    Instruction{ .crc32h = payload }
                else if (width == .w and s == 0 and opcode == 0b010010)
                    Instruction{ .crc32w = payload }
                else if (width == .w and s == 0 and opcode == 0b010100)
                    Instruction{ .crc32cb = payload }
                else if (width == .w and s == 0 and opcode == 0b010101)
                    Instruction{ .crc32ch = payload }
                else if (width == .w and s == 0 and opcode == 0b010110)
                    Instruction{ .crc32cw = payload }
                else if (width == .x and s == 0 and opcode == 0b000000)
                    Instruction{ .subp = payload }
                else if (width == .x and s == 0 and opcode == 0b000100)
                    Instruction{ .irg = payload }
                else if (width == .x and s == 0 and opcode == 0b000101)
                    Instruction{ .gmi = payload }
                else if (width == .x and s == 0 and opcode == 0b001100)
                    Instruction{ .pacga = payload }
                else if (width == .x and s == 0 and opcode == 0b010011)
                    Instruction{ .crc32x = payload }
                else if (width == .x and s == 0 and opcode == 0b010111)
                    Instruction{ .crc32cx = payload }
                else if (width == .x and s == 0 and opcode == 0b000000)
                    Instruction{ .subps = payload }
                else
                    error.Unallocated;
            },

            0b1000, 0b1001, 0b1010, 0b1011, 0b1100, 0b1101, 0b1110, 0b1111 => { // data processing 3 source
                const width = Width.from(op >> 31);
                const op54 = @truncate(u2, op >> 29);
                const op31 = @truncate(u3, op >> 21);
                const o0 = @truncate(u1, op >> 15);
                const payload = DataProcInstr{
                    .rm = if (op31 == 0b000)
                        Register.from(op >> 16, width, false)
                    else if (op31 == 0b010 or op31 == 0b110)
                        Register.from(op >> 16, .x, false)
                    else
                        Register.from(op >> 16, .w, false),
                    .ra = Register.from(op >> 10, width, false),
                    .rn = if (op31 == 0b000)
                        Register.from(op >> 5, width, false)
                    else if (op31 == 0b010 or op31 == 0b110)
                        Register.from(op >> 5, .x, false)
                    else
                        Register.from(op >> 5, .w, false),
                    .rd = Register.from(op >> 0, width, false),
                };
                return if (op54 != 0b00)
                    error.Unallocated
                else if (op31 == 0 and o0 == 0)
                    Instruction{ .madd = payload }
                else if (op31 == 0 and o0 == 1)
                    Instruction{ .msub = payload }
                else if (width == .x and op31 == 0b001 and o0 == 0)
                    Instruction{ .smaddl = payload }
                else if (width == .x and op31 == 0b001 and o0 == 1)
                    Instruction{ .smsubl = payload }
                else if (width == .x and op31 == 0b010 and o0 == 0)
                    Instruction{ .smulh = payload }
                else if (width == .x and op31 == 0b101 and o0 == 0)
                    Instruction{ .umaddl = payload }
                else if (width == .x and op31 == 0b101 and o0 == 1)
                    Instruction{ .umsubl = payload }
                else if (width == .x and op31 == 0b110 and o0 == 0)
                    Instruction{ .umulh = payload }
                else
                    error.Unallocated;
            },
            else => return error.Unallocated,
        };
    }

    fn decodeDataProcScalarFPSIMD(op: u32) Error!Instruction {
        const op0 = @truncate(u4, op >> 28);
        const op1 = @truncate(u2, op >> 23);
        const op2 = @truncate(u4, op >> 19);
        const op3 = @truncate(u9, op >> 10);
        return if (op0 == 0b0100 and (op1 == 0b00 or op1 == 0b01) and @truncate(u3, op2) == 0b101 and
            @truncate(u2, op3) == 0b10 and @truncate(u2, op3 >> 8) == 0b00)
            @panic("crypto aes")
        else if (op0 == 0b0101 and (op1 == 0b00 or op1 == 0b01) and @truncate(u1, op2 >> 2) == 0b0 and
            @truncate(u2, op3) == 0b00 and @truncate(u1, op3 >> 5) == 0b0)
            @panic("crypto 3reg sha")
        else if (op0 == 0b0101 and (op1 == 0b00 or op1 == 0b01) and @truncate(u3, op2) == 0b101 and
            @truncate(u2, op3) == 0b10 and @truncate(u2, op3 >> 8) == 0b00)
            @panic("crypto 2reg sha")
        else
            error.Unimplemented;
    }
};
