const std = @import("std");
const Register = @import("utils.zig").Register;
const Width = @import("utils.zig").Width;
const Field = @import("utils.zig").Field;

const AddSubInstr = @import("instruction.zig").AddSubInstr;
const BitfieldInstr = @import("instruction.zig").BitfieldInstr;
const ConCompInstr = @import("instruction.zig").ConCompInstr;
const Condition = @import("instruction.zig").Condition;
const DataProcInstr = @import("instruction.zig").DataProcInstr;
const ExtractInstr = @import("instruction.zig").ExtractInstr;
const Instruction = @import("instruction.zig").Instruction;
const LogInstr = @import("instruction.zig").LogInstr;
const MovInstr = @import("instruction.zig").MovInstr;
const PCRelAddrInstr = @import("instruction.zig").PCRelAddrInstr;

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
            0b0111, 0b1111 => return error.Unimplemented, // Data processing - Scalar FP and SIMD
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
                    .width = width,
                    .rn = Register.from(op >> 5, width, true),
                    .rd = Register.from(op, width, true),
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
                    .rd = Register.from(op, width, false),
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
        return switch (op0) {
            else => error.Unimplemented,
        };
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
                    .width = width,
                    .rn = Register.from(op >> 5, width, false),
                    .rd = Register.from(op, width, false),
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
                    const add = @truncate(u1, op >> 30) == 0;
                    const width = Width.from(op >> 31);
                    const payload = AddSubInstr{
                        .s = @truncate(u1, op >> 29) == 1,
                        .width = width,
                        .rn = Register.from(op >> 5, width, false),
                        .rd = Register.from(op, width, false),
                        .payload = .{ .carry = Register.from(op >> 16, width, false) },
                    };
                    return if (add)
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
                    .rm = if (one_source) Register.from(op >> 16, width, false) else null,
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
                    .rm = Register.from(op >> 16, width, false),
                    .ra = Register.from(op >> 10, width, false),
                    .rn = Register.from(op >> 5, width, false),
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
};

test "arithmetic" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var disassembler = Disassembler.init(&.{
        // Add/Subtract with carry/borrow
        0x41, 0x00, 0x03, 0x1a,
        0x41, 0x00, 0x03, 0x9a,
        0x85, 0x00, 0x03, 0x3a,
        0x85, 0x00, 0x03, 0xba,
        0x41, 0x00, 0x03, 0x5a,
        0x41, 0x00, 0x03, 0xda,
        0x41, 0x00, 0x03, 0x7a,
        0x41, 0x00, 0x03, 0xfa,
        // Add/Subtract with (optionally shifted) immediate
        0x83, 0x00, 0x10, 0x11,
        0x83, 0x00, 0x10, 0x91,
        0x83, 0x00, 0x50, 0x11,
        0x83, 0x00, 0x40, 0x11,
        0x83, 0x00, 0x50, 0x91,
        0x83, 0x00, 0x40, 0x91,
        0xff, 0x83, 0x00, 0x91,
        0x83, 0x00, 0x10, 0x31,
        0x83, 0x00, 0x50, 0x31,
        0x83, 0x00, 0x10, 0xb1,
        0x83, 0x00, 0x50, 0xb1,
        0xff, 0x83, 0x00, 0xb1,
        0x83, 0x00, 0x10, 0x51,
        0x83, 0x00, 0x50, 0x51,
        0x83, 0x00, 0x10, 0xd1,
        0x83, 0x00, 0x50, 0xd1,
        0xff, 0x83, 0x00, 0xd1,
        0x83, 0x00, 0x10, 0x71,
        0x83, 0x00, 0x50, 0x71,
        0x83, 0x00, 0x10, 0xf1,
        0x83, 0x00, 0x50, 0xf1,
        0xff, 0x83, 0x00, 0xf1,
        // Add/Subtract register with (optional) shift
        0xac, 0x01, 0x0e, 0x0b,
        0xac, 0x01, 0x0e, 0x8b,
        0xac, 0x31, 0x0e, 0x0b,
        0xac, 0x31, 0x0e, 0x8b,
        0xac, 0x29, 0x4e, 0x0b,
        0xac, 0x29, 0x4e, 0x8b,
        0xac, 0x1d, 0x8e, 0x0b,
        0xac, 0x9d, 0x8e, 0x8b,
        0xac, 0x01, 0x0e, 0x4b,
        0xac, 0x01, 0x0e, 0xcb,
        0xac, 0x31, 0x0e, 0x4b,
        0xac, 0x31, 0x0e, 0xcb,
        0xac, 0x29, 0x4e, 0x4b,
        0xac, 0x29, 0x4e, 0xcb,
        0xac, 0x1d, 0x8e, 0x4b,
        0xac, 0x9d, 0x8e, 0xcb,
        0xac, 0x01, 0x0e, 0x2b,
        0xac, 0x01, 0x0e, 0xab,
        0xac, 0x31, 0x0e, 0x2b,
        0xac, 0x31, 0x0e, 0xab,
        0xac, 0x29, 0x4e, 0x2b,
        0xac, 0x29, 0x4e, 0xab,
        0xac, 0x1d, 0x8e, 0x2b,
        0xac, 0x9d, 0x8e, 0xab,
        0xac, 0x01, 0x0e, 0x6b,
        0xac, 0x01, 0x0e, 0xeb,
        0xac, 0x31, 0x0e, 0x6b,
        0xac, 0x31, 0x0e, 0xeb,
        0xac, 0x29, 0x4e, 0x6b,
        0xac, 0x29, 0x4e, 0xeb,
        0xac, 0x1d, 0x8e, 0x6b,
        0xac, 0x9d, 0x8e, 0xeb,
        // Add/Subtract with (optional) extend
        0x41, 0x00, 0x23, 0x0b,
        0x41, 0x20, 0x23, 0x0b,
        0x41, 0x40, 0x23, 0x0b,
        0x41, 0x60, 0x23, 0x0b,
        0x41, 0x80, 0x23, 0x0b,
        0x41, 0xa0, 0x23, 0x0b,
        0x41, 0xc0, 0x23, 0x0b,
        0x41, 0xe0, 0x23, 0x0b,
        0x41, 0x00, 0x23, 0x8b,
        0x41, 0x20, 0x23, 0x8b,
        0x41, 0x40, 0x23, 0x8b,
        0x41, 0x80, 0x23, 0x8b,
        0x41, 0xa0, 0x23, 0x8b,
        0x41, 0xc0, 0x23, 0x8b,
        0xe1, 0x43, 0x23, 0x0b,
        0xe1, 0x43, 0x23, 0x0b,
        0x5f, 0x60, 0x23, 0x8b,
        0x5f, 0x60, 0x23, 0x8b,
        0x41, 0x00, 0x23, 0x4b,
        0x41, 0x20, 0x23, 0x4b,
        0x41, 0x40, 0x23, 0x4b,
        0x41, 0x60, 0x23, 0x4b,
        0x41, 0x80, 0x23, 0x4b,
        0x41, 0xa0, 0x23, 0x4b,
        0x41, 0xc0, 0x23, 0x4b,
        0x41, 0xe0, 0x23, 0x4b,
        0x41, 0x00, 0x23, 0xcb,
        0x41, 0x20, 0x23, 0xcb,
        0x41, 0x40, 0x23, 0xcb,
        0x41, 0x80, 0x23, 0xcb,
        0x41, 0xa0, 0x23, 0xcb,
        0x41, 0xc0, 0x23, 0xcb,
        0xe1, 0x43, 0x23, 0x4b,
        0xe1, 0x43, 0x23, 0x4b,
        0x5f, 0x60, 0x23, 0xcb,
        0x5f, 0x60, 0x23, 0xcb,
        0x41, 0x00, 0x23, 0x2b,
        0x41, 0x20, 0x23, 0x2b,
        0x41, 0x40, 0x23, 0x2b,
        0x41, 0x60, 0x23, 0x2b,
        0x41, 0x80, 0x23, 0x2b,
        0x41, 0xa0, 0x23, 0x2b,
        0x41, 0xc0, 0x23, 0x2b,
        0x41, 0xe0, 0x23, 0x2b,
        0x41, 0x00, 0x23, 0xab,
        0x41, 0x20, 0x23, 0xab,
        0x41, 0x40, 0x23, 0xab,
        0x41, 0x80, 0x23, 0xab,
        0x41, 0xa0, 0x23, 0xab,
        0x41, 0xc0, 0x23, 0xab,
        0xe1, 0x43, 0x23, 0x2b,
        0xe1, 0x43, 0x23, 0x2b,
        0x41, 0x00, 0x23, 0x6b,
        0x41, 0x20, 0x23, 0x6b,
        0x41, 0x40, 0x23, 0x6b,
        0x41, 0x60, 0x23, 0x6b,
        0x41, 0x80, 0x23, 0x6b,
        0x41, 0xa0, 0x23, 0x6b,
        0x41, 0xc0, 0x23, 0x6b,
        0x41, 0xe0, 0x23, 0x6b,
        0x41, 0x00, 0x23, 0xeb,
        0x41, 0x20, 0x23, 0xeb,
        0x41, 0x40, 0x23, 0xeb,
        0x41, 0x80, 0x23, 0xeb,
        0x41, 0xa0, 0x23, 0xeb,
        0x41, 0xc0, 0x23, 0xeb,
        0xe1, 0x43, 0x23, 0x6b,
        0xe1, 0x43, 0x23, 0x6b,
        0x1f, 0x41, 0x28, 0xeb,
        0x3f, 0x41, 0x28, 0x6b,
        0xff, 0x43, 0x28, 0x6b,
        0xff, 0x43, 0x28, 0xeb,
        0x3f, 0x41, 0x28, 0x4b,
        0xe1, 0x43, 0x28, 0x4b,
        0xff, 0x43, 0x28, 0x4b,
        0x3f, 0x41, 0x28, 0xcb,
        0xe1, 0x43, 0x28, 0xcb,
        0xff, 0x43, 0x28, 0xcb,
        0xe1, 0x43, 0x28, 0x6b,
        0xe1, 0x43, 0x28, 0xeb,
        // Signed/Unsigned divide
        0x41, 0x0c, 0xc3, 0x1a,
        0x41, 0x0c, 0xc3, 0x9a,
        0x41, 0x08, 0xc3, 0x1a,
        0x41, 0x08, 0xc3, 0x9a,
        // Variable shifts
        0x41, 0x28, 0xc3, 0x1a,
        0x41, 0x28, 0xc3, 0x9a,
        0x41, 0x20, 0xc3, 0x1a,
        0x41, 0x20, 0xc3, 0x9a,
        0x41, 0x24, 0xc3, 0x1a,
        0x41, 0x24, 0xc3, 0x9a,
        0x41, 0x2c, 0xc3, 0x1a,
        0x41, 0x2c, 0xc3, 0x9a,
        // One operand instructions
        0x41, 0x14, 0xc0, 0x5a,
        0x41, 0x14, 0xc0, 0xda,
        0x41, 0x10, 0xc0, 0x5a,
        0x41, 0x10, 0xc0, 0xda,
        0x41, 0x00, 0xc0, 0x5a,
        0x41, 0x00, 0xc0, 0xda,
        0x41, 0x08, 0xc0, 0x5a,
        0x41, 0x0c, 0xc0, 0xda,
        0x41, 0x04, 0xc0, 0x5a,
        0x41, 0x04, 0xc0, 0xda,
        0x41, 0x08, 0xc0, 0xda,
        // 6.6.1 Multiply-add instructions
        0x41, 0x10, 0x03, 0x1b,
        0x41, 0x10, 0x03, 0x9b,
        0x41, 0x90, 0x03, 0x1b,
        0x41, 0x90, 0x03, 0x9b,
        0x41, 0x10, 0x23, 0x9b,
        0x41, 0x90, 0x23, 0x9b,
        0x41, 0x10, 0xa3, 0x9b,
        0x41, 0x90, 0xa3, 0x9b,
        // Multiply-high instructions
        0x41, 0x7c, 0x43, 0x9b,
        0x41, 0x7c, 0xc3, 0x9b,
        // Move immediate instructions
        0x20, 0x00, 0x80, 0x52,
        0x20, 0x00, 0x80, 0xd2,
        0x20, 0x00, 0xa0, 0x52,
        0x20, 0x00, 0xa0, 0xd2,
        0x40, 0x00, 0x80, 0x12,
        0x40, 0x00, 0x80, 0x92,
        0x40, 0x00, 0xa0, 0x12,
        0x40, 0x00, 0xa0, 0x92,
        0x20, 0x00, 0x80, 0x72,
        0x20, 0x00, 0x80, 0xf2,
        0x20, 0x00, 0xa0, 0x72,
        0x20, 0x00, 0xa0, 0xf2,
        // Conditionally set flags instructions
        0x1f, 0x00, 0x00, 0x31,
        0x1f, 0xfc, 0x03, 0xb1,
        0x23, 0x08, 0x42, 0x3a,
        0x23, 0x08, 0x42, 0xba,
        0x23, 0x08, 0x42, 0x7a,
        0x23, 0x08, 0x42, 0xfa,
        0x23, 0x00, 0x42, 0x3a,
        0x23, 0x00, 0x42, 0xba,
        0x23, 0x00, 0x42, 0x7a,
        0x23, 0x00, 0x42, 0xfa,
        // Conditional select instructions
        0x41, 0x00, 0x83, 0x1a,
        0x41, 0x00, 0x83, 0x9a,
        0x41, 0x04, 0x83, 0x1a,
        0x41, 0x04, 0x83, 0x9a,
        0x41, 0x00, 0x83, 0x5a,
        0x41, 0x00, 0x83, 0xda,
        0x41, 0x04, 0x83, 0x5a,
        0x41, 0x04, 0x83, 0xda,
    });

    var text = std.ArrayList(u8).init(gpa.allocator());
    defer text.deinit();

    while (try disassembler.next()) |inst| {
        try inst.fmtPrint(text.writer());
        try text.append('\n');
    }

    try std.testing.expectEqualStrings(
        \\adc w1, w2, w3
        \\adc x1, x2, x3
        \\adcs w5, w4, w3
        \\adcs x5, x4, x3
        \\sbc w1, w2, w3
        \\sbc x1, x2, x3
        \\sbcs w1, w2, w3
        \\sbcs x1, x2, x3
        \\add w3, w4, #1024
        \\add x3, x4, #1024
        \\add w3, w4, #1024, lsl #12
        \\add w3, w4, #0, lsl #12
        \\add x3, x4, #1024, lsl #12
        \\add x3, x4, #0, lsl #12
        \\add sp, sp, #32
        \\adds w3, w4, #1024
        \\adds w3, w4, #1024, lsl #12
        \\adds x3, x4, #1024
        \\adds x3, x4, #1024, lsl #12
        \\cmn sp, #32
        \\sub w3, w4, #1024
        \\sub w3, w4, #1024, lsl #12
        \\sub x3, x4, #1024
        \\sub x3, x4, #1024, lsl #12
        \\sub sp, sp, #32
        \\subs w3, w4, #1024
        \\subs w3, w4, #1024, lsl #12
        \\subs x3, x4, #1024
        \\subs x3, x4, #1024, lsl #12
        \\cmp sp, #32
        \\add w12, w13, w14
        \\add x12, x13, x14
        \\add w12, w13, w14, lsl #12
        \\add x12, x13, x14, lsl #12
        \\add w12, w13, w14, lsr #10
        \\add x12, x13, x14, lsr #10
        \\add w12, w13, w14, asr #7
        \\add x12, x13, x14, asr #39
        \\sub w12, w13, w14
        \\sub x12, x13, x14
        \\sub w12, w13, w14, lsl #12
        \\sub x12, x13, x14, lsl #12
        \\sub w12, w13, w14, lsr #10
        \\sub x12, x13, x14, lsr #10
        \\sub w12, w13, w14, asr #7
        \\sub x12, x13, x14, asr #39
        \\adds w12, w13, w14
        \\adds x12, x13, x14
        \\adds w12, w13, w14, lsl #12
        \\adds x12, x13, x14, lsl #12
        \\adds w12, w13, w14, lsr #10
        \\adds x12, x13, x14, lsr #10
        \\adds w12, w13, w14, asr #7
        \\adds x12, x13, x14, asr #39
        \\subs w12, w13, w14
        \\subs x12, x13, x14
        \\subs w12, w13, w14, lsl #12
        \\subs x12, x13, x14, lsl #12
        \\subs w12, w13, w14, lsr #10
        \\subs x12, x13, x14, lsr #10
        \\subs w12, w13, w14, asr #7
        \\subs x12, x13, x14, asr #39
        \\add w1, w2, w3, uxtb
        \\add w1, w2, w3, uxth
        \\add w1, w2, w3
        \\add w1, w2, w3, uxtx
        \\add w1, w2, w3, sxtb
        \\add w1, w2, w3, sxth
        \\add w1, w2, w3, sxtw
        \\add w1, w2, w3, sxtx
        \\add x1, x2, w3, uxtb
        \\add x1, x2, w3, uxth
        \\add x1, x2, w3, uxtw
        \\add x1, x2, w3, sxtb
        \\add x1, x2, w3, sxth
        \\add x1, x2, w3, sxtw
        \\add w1, wsp, w3
        \\add w1, wsp, w3
        \\add sp, x2, x3
        \\add sp, x2, x3
        \\sub w1, w2, w3, uxtb
        \\sub w1, w2, w3, uxth
        \\sub w1, w2, w3
        \\sub w1, w2, w3, uxtx
        \\sub w1, w2, w3, sxtb
        \\sub w1, w2, w3, sxth
        \\sub w1, w2, w3, sxtw
        \\sub w1, w2, w3, sxtx
        \\sub x1, x2, w3, uxtb
        \\sub x1, x2, w3, uxth
        \\sub x1, x2, w3, uxtw
        \\sub x1, x2, w3, sxtb
        \\sub x1, x2, w3, sxth
        \\sub x1, x2, w3, sxtw
        \\sub w1, wsp, w3
        \\sub w1, wsp, w3
        \\sub sp, x2, x3
        \\sub sp, x2, x3
        \\adds w1, w2, w3, uxtb
        \\adds w1, w2, w3, uxth
        \\adds w1, w2, w3
        \\adds w1, w2, w3, uxtx
        \\adds w1, w2, w3, sxtb
        \\adds w1, w2, w3, sxth
        \\adds w1, w2, w3, sxtw
        \\adds w1, w2, w3, sxtx
        \\adds x1, x2, w3, uxtb
        \\adds x1, x2, w3, uxth
        \\adds x1, x2, w3, uxtw
        \\adds x1, x2, w3, sxtb
        \\adds x1, x2, w3, sxth
        \\adds x1, x2, w3, sxtw
        \\adds w1, wsp, w3
        \\adds w1, wsp, w3
        \\subs w1, w2, w3, uxtb
        \\subs w1, w2, w3, uxth
        \\subs w1, w2, w3
        \\subs w1, w2, w3, uxtx
        \\subs w1, w2, w3, sxtb
        \\subs w1, w2, w3, sxth
        \\subs w1, w2, w3, sxtw
        \\subs w1, w2, w3, sxtx
        \\subs x1, x2, w3, uxtb
        \\subs x1, x2, w3, uxth
        \\subs x1, x2, w3, uxtw
        \\subs x1, x2, w3, sxtb
        \\subs x1, x2, w3, sxth
        \\subs x1, x2, w3, sxtw
        \\subs w1, wsp, w3
        \\subs w1, wsp, w3
        \\cmp x8, w8, uxtw
        \\cmp w9, w8, uxtw
        \\cmp wsp, w8
        \\cmp sp, w8
        \\sub wsp, w9, w8
        \\sub w1, wsp, w8
        \\sub wsp, wsp, w8
        \\sub sp, x9, w8
        \\sub x1, sp, w8
        \\sub sp, sp, w8
        \\subs w1, wsp, w8
        \\subs x1, sp, w8
        \\sdiv w1, w2, w3
        \\sdiv x1, x2, x3
        \\udiv w1, w2, w3
        \\udiv x1, x2, x3
        \\asr w1, w2, w3
        \\asr x1, x2, x3
        \\lsl w1, w2, w3
        \\lsl x1, x2, x3
        \\lsr w1, w2, w3
        \\lsr x1, x2, x3
        \\ror w1, w2, w3
        \\ror x1, x2, x3
        \\cls w1, w2
        \\cls x1, x2
        \\clz w1, w2
        \\clz x1, x2
        \\rbit w1, w2
        \\rbit x1, x2
        \\rev w1, w2
        \\rev x1, x2
        \\rev16 w1, w2
        \\rev16 x1, x2
        \\rev32 x1, x2
        \\madd w1, w2, w3, w4
        \\madd x1, x2, x3, x4
        \\msub w1, w2, w3, w4
        \\msub x1, x2, x3, x4
        \\smaddl x1, w2, w3, x4
        \\smsubl x1, w2, w3, x4
        \\umaddl x1, w2, w3, x4
        \\umsubl x1, w2, w3, x4
        \\smulh x1, x2, x3
        \\umulh x1, x2, x3
        \\mov w0, #1
        \\mov x0, #1
        \\mov w0, #65536
        \\mov x0, #65536
        \\mov w0, #-3
        \\mov x0, #-3
        \\mov w0, #-131073
        \\mov x0, #-131073
        \\movk w0, #1
        \\movk x0, #1
        \\movk w0, #1, lsl #16
        \\movk x0, #1, lsl #16
        \\cmn w0, #0
        \\cmn x0, #0xff
        \\ccmn w1, #2, #3, eq
        \\ccmn x1, #2, #3, eq
        \\ccmp w1, #2, #3, eq
        \\ccmp x1, #2, #3, eq
        \\ccmn w1, w2, #3, eq
        \\ccmn x1, x2, #3, eq
        \\ccmp w1, w2, #3, eq
        \\ccmp x1, x2, #3, eq
        \\csel w1, w2, w3, eq
        \\csel x1, x2, x3, eq
        \\csinc w1, w2, w3, eq
        \\csinc x1, x2, x3, eq
        \\csinv w1, w2, w3, eq
        \\csinv x1, x2, x3, eq
        \\csneg w1, w2, w3, eq
        \\csneg x1, x2, x3, eq
        \\
    , text.items);
}

test "bitfield" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var disassembler = Disassembler.init(&.{
        // 5.4.4 Bitfield Operations
        0x41, 0x3c, 0x01, 0x33,
        0x41, 0x3c, 0x41, 0xb3,
        0x41, 0x3c, 0x01, 0x13,
        0x41, 0x3c, 0x41, 0x93,
        0x41, 0x3c, 0x01, 0x53,
        0x41, 0x3c, 0x41, 0xd3,
        // 5.4.5 Extract (immediate)
        0x41, 0x3c, 0x83, 0x13,
        0x62, 0x04, 0xc4, 0x93,
    });

    var text = std.ArrayList(u8).init(gpa.allocator());
    defer text.deinit();

    while (try disassembler.next()) |inst| {
        try inst.fmtPrint(text.writer());
        try text.append('\n');
    }

    try std.testing.expectEqualStrings(
        \\bfxil w1, w2, #1, #15
        \\bfxil x1, x2, #1, #15
        \\sbfx w1, w2, #1, #15
        \\sbfx x1, x2, #1, #15
        \\ubfx w1, w2, #1, #15
        \\ubfx x1, x2, #1, #15
        \\extr w1, w2, w3, #15
        \\extr x2, x3, x4, #1
        \\
    , text.items);
}
