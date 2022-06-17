const std = @import("std");
const Instruction = @import("instruction.zig").Instruction;
const AddSubInstr = @import("instruction.zig").AddSubInstr;
const LogInstr = @import("instruction.zig").LogInstr;
const Register = @import("utils.zig").Register;
const Width = @import("utils.zig").Width;
const Field = @import("utils.zig").Field;
const bytes = @import("utils.zig").bytes;

const Error = error{
    EndOfStream,
    Unallocated,
    Unimplemented,
};

const Disassembler = struct {
    const Self = @This();

    code: []const u8,
    stream: std.io.FixedBufferStream([]const u8),

    pub fn init(code: []const u8) Self {
        return .{
            .code = code,
            .stream = std.io.fixedBufferStream(code),
        };
    }

    fn next(self: *Self) Error!?Instruction {
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
        return if (op >> 16 == 0x0) .{ .UDF = @truncate(u16, op) } else error.Unimplemented;
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
            0b000, 0b001 => .{ // pc rel
                .ADR = .{
                    .p = (op >> 31) == 1,
                    .immhi = bytes(u19, op >> 5),
                    .immlo = bytes(u2, op >> 29),
                    .rd = Register.from(@truncate(u5, op), .x, false),
                },
            },
            0b010 => blk: { // add/sub
                const width = Width.from(op >> 31);
                const add = (op >> 30) == 0;
                const s = @truncate(u1, op >> 29) == 0x1;
                const payload = .{
                    .s = s,
                    .width = width,
                    .rn = Register.from(@truncate(u5, op >> 5), width, s),
                    .rd = Register.from(@truncate(u5, op), width, true),
                    .payload = .{ .imm12 = bytes(u12, op >> 10) },
                };
                break :blk if (add) Instruction{ .ADD = payload } else Instruction{ .SUB = payload };
            },
            0b011 => blk: { // add/sub with tags
                const width = .x;
                const sf = op >> 31 == 0x1;
                const add = (op >> 30) == 0;
                const s = @truncate(u1, op >> 29);
                const o2 = @truncate(u1, op >> 22);
                const payload = .{
                    .s = false,
                    .width = width,
                    .rn = Register.from(@truncate(u5, op >> 5), .x, true),
                    .rd = Register.from(@truncate(u5, op), .x, true),
                    .payload = .{ .imm_tag = .{
                        .uimm6 = bytes(u6, op >> 16),
                        .uimm4 = bytes(u4, op >> 10),
                    } },
                };
                break :blk if (sf and s == 0x0 and o2 == 0x0)
                    if (add) Instruction{ .ADD = payload } else Instruction{ .SUB = payload }
                else
                    error.Unallocated;
            },
            0b100 => blk: { // logical
                const width = Width.from(op >> 31);
                const opc = @truncate(u2, op >> 29);
                const n = @truncate(u1, op >> 22);
                const s = opc == 0b11;
                const payload = .{
                    .s = s,
                    .width = width,
                    .rn = Register.from(@truncate(u5, op >> 5), width, !s),
                    .rd = Register.from(@truncate(u5, op), width, !s),
                    .payload = .{ .imm = .{
                        .immr = bytes(u6, op >> 16),
                        .imms = bytes(u6, op >> 10),
                    } },
                };
                break :blk if (@enumToInt(width) == 0 and n == 1) error.Unallocated else switch (opc) {
                    0b00, 0b11 => Instruction{ .AND = payload },
                    0b01 => Instruction{ .ORR = payload },
                    0b10 => Instruction{ .EOR = payload },
                };
            },
            0b101 => blk: { // move wide
                const width = Width.from(op >> 31);
                const hw = @truncate(u2, op >> 21);
                const opc = @truncate(u2, op >> 29);
                break :blk if (opc == 0b01 or (width == .w and (hw == 0b10 or hw == 0b11)))
                    error.Unallocated
                else .{ .MOV = .{
                    .width = width,
                    .ext = @intToEnum(Field(Field(Instruction, .MOV), .ext), opc),
                    .imm16 = bytes(u16, op >> 5),
                    .rd = Register.from(@truncate(u5, op), width, false),
                } };
            },
            0b110 => blk: { // bitfield
                const width = Width.from(op >> 31);
                const opc = @truncate(u2, op >> 29);
                const n = @truncate(u1, op >> 22);
                break :blk if (opc == 0b11 or @enumToInt(width) != n)
                    error.Unallocated
                else .{ .BFM = .{
                    .width = width,
                    .tag = @intToEnum(Field(Field(Instruction, .BFM), .tag), opc),
                    .immr = bytes(u6, op >> 16),
                    .imms = bytes(u6, op >> 10),
                    .rn = Register.from(@truncate(u5, op >> 5), width, false),
                    .rd = Register.from(@truncate(u5, op), width, false),
                } };
            },
            0b111 => blk: { // extract
                const width = Width.from(op >> 31);
                const op21 = @truncate(u2, op >> 29);
                const n = @truncate(u1, op >> 22);
                const o0 = @truncate(u1, op >> 21);
                const imms = bytes(u6, op >> 10);
                break :blk if ((@enumToInt(width) == 1 and op21 == 0x0 and n == 0x1 and o0 == 0x0) or
                    (@enumToInt(width) == 0 and op21 == 0x0 and n == 0x0 and o0 == 0x0 and imms < 0b100000))
                .{ .EXTR = .{
                    .width = width,
                    .rm = Register.from(@truncate(u5, op >> 16), width, false),
                    .imms = imms,
                    .rn = Register.from(@truncate(u5, op >> 5), width, false),
                    .rd = Register.from(@truncate(u5, op), width, false),
                } } else error.Unallocated;
            },
        };
    }

    fn decodeBranchExcpSysInstr(op: u32) Error!Instruction {
        const op0 = @truncate(u3, op >> 29);
        return switch (op0) {
            0b010 => error.Unimplemented, // conditional branch, imm
            0b110 => error.Unimplemented,
            0b000, 0b100 => .{ // unconditional branch, imm
                .B = .{
                    .l = (op >> 31) == 1,
                    .imm26 = bytes(u26, op),
                },
            },
            0b001, 0b101 => blk: { // {compare,test} and branch
                const width = Width.from(@truncate(u1, op >> 31));
                const n = @truncate(u1, op >> 24) == 1;
                if (@truncate(u1, op >> 25) == 1) { // compare and branch
                    break :blk Instruction{ .CBZ = .{
                        .n = n,
                        .width = width,
                        .imm19 = bytes(u19, op >> 5),
                        .rt = Register.from(@truncate(u5, op), width, false),
                    } };
                } else { // test and branch
                    break :blk Instruction{ .TBZ = .{
                        .n = n,
                        .width = width,
                        .b40 = @truncate(u5, op >> 19),
                        .imm14 = bytes(u14, op >> 5),
                        .rt = Register.from(@truncate(u5, op), width, false),
                    } };
                }
            },
            0b011, 0b111 => unreachable,
        };
    }

    fn decodeDataProcReg(op: u32) Error!Instruction {
        const op0 = @truncate(u1, op >> 30);
        const op1 = @truncate(u1, op >> 28);
        const op2 = @truncate(u4, op >> 21);
        const op3 = @truncate(u6, op >> 10);
        _ = op0;
        _ = op3;
        if (op1 == 0) {
            switch (op2) {
                0b0000...0b0111 => blk: { // log shift reg
                    const width = Width.from(op >> 31);
                    const opc = @truncate(u2, op >> 29);
                    const n = @truncate(u1, op >> 21) == 1;
                    const imm6 = bytes(u6, op >> 10);
                    const payload = .{
                        .s = opc == 0b11,
                        .width = width,
                        .rn = Register.from(@truncate(u5, op >> 5), width, false),
                        .rd = Register.from(@truncate(u5, op), width, false),
                        .payload = .{
                            .rm = Register.from(@truncate(u5, op >> 16), width, false),
                            .imm6 = bytes(u6, op >> 10),
                            .n = n,
                        },
                    };
                    break :blk if (width == .w and imm6 >= 0b100000)
                        error.Unallocated
                    else switch (opc) {
                        0b00, 0b11 => Instruction{ .AND = payload },
                        0b01 => Instruction{ .ORR = payload },
                        0b10 => Instruction{ .EOR = payload },
                    };
                },
                0b1000, 0b1010, 0b1100, 0b1110 => return error.Unimplemented, // add/sub shift reg
                0b1001, 0b1011, 0b1101, 0b1111 => return error.Unimplemented, // add/sub ext reg
            }
        } else {
            return error.Unimplemented;
        }
    }
};

test "disassembler functionality" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var disassembler = Disassembler.init(&.{
        0x41, 0x01, 0x80, 0xD2, // mov x1, #xa
        0xE1, 0x03, 0x00, 0xAA, // mov x1, x0
    });

    var text = std.ArrayList(u8).init(gpa.allocator());
    defer text.deinit();

    while (try disassembler.next()) |inst| {
        try inst.fmtPrint(text.writer());
        try text.append('\n');
    }

    try std.testing.expectEqualStrings(
        \\movz x1, #0xa
        \\mov x1, x0
        \\
    , text.items);
}
