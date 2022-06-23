const std = @import("std");
const Disassembler = @import("decoder.zig").Disassembler;

pub fn main() anyerror!void {
    var gpa_alloc = std.heap.GeneralPurposeAllocator(.{}){};
    const gpa = gpa_alloc.allocator();
    const args = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, args);

    if (args.len == 0) {
        std.debug.print("Send hex input in through arguments", .{});
        std.process.exit(1);
    }
    const input_hex = args[1];
    const hex_len = @divExact(input_hex.len, 2);

    var i: usize = 0;
    var bytes = std.ArrayList(u8).init(gpa);
    try bytes.ensureTotalCapacity(hex_len);
    defer bytes.deinit();

    while (i < hex_len) : (i += 1) {
        const next_hex = input_hex[i * 2 .. (i + 1) * 2];
        bytes.appendAssumeCapacity(try std.fmt.parseInt(u8, next_hex, 16));
    }

    var buf = std.ArrayList(u8).init(gpa);
    defer buf.deinit();

    var disassembler = Disassembler.init(bytes.items);
    while (try disassembler.next()) |inst| {
        try inst.fmtPrint(buf.writer());
        try buf.append('\n');
    }

    const stdout = std.io.getStdOut().writer();
    try stdout.writeAll("disassembled:\n");
    try stdout.print("  {s}  {s}", .{ input_hex, buf.items });
}
