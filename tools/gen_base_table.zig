//! Generate the Ed25519 fixed-base table used by the GPU shaders.
//!
//! base[i][j] = (j + 1) * 256^i * B, stored as (y+x, y-x, 2*d*x*y)
//! in canonical 51-bit limbs. The search checks these limbs by
//! replaying the shader's addition chain against std.crypto.
const std = @import("std");

const Edwards = std.crypto.ecc.Edwards25519;
const Fe = Edwards.Fe;

const Precomp = struct {
    yplusx: Fe,
    yminusx: Fe,
    xy2d: Fe,
};

const P3 = struct {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,

    const identity = P3{ .x = Fe.zero, .y = Fe.one, .z = Fe.one, .t = Fe.zero };

    fn toBytes(p: P3) [32]u8 {
        const zi = p.z.invert();
        var s = p.y.mul(zi).toBytes();
        s[31] ^= @as(u8, @intFromBool(p.x.mul(zi).isNegative())) << 7;
        return s;
    }
};

fn toPrecomp(p: Edwards) Precomp {
    const zi = p.z.invert();
    const x = p.x.mul(zi);
    const y = p.y.mul(zi);
    return .{
        .yplusx = y.add(x),
        .yminusx = y.sub(x),
        .xy2d = x.mul(y).mul(Fe.edwards25519d2),
    };
}

fn madd(p: P3, q: Precomp) P3 {
    const ypx = p.y.add(p.x).mul(q.yplusx);
    const ymx = p.y.sub(p.x).mul(q.yminusx);
    const xy2 = q.xy2d.mul(p.t);
    const z2 = p.z.add(p.z);
    const x = ypx.sub(ymx);
    const y = ypx.add(ymx);
    const z = z2.add(xy2);
    const t = z2.sub(xy2);
    return .{
        .x = x.mul(t),
        .y = y.mul(z),
        .z = z.mul(t),
        .t = x.mul(y),
    };
}

fn dbl(p: P3) P3 {
    const point = Edwards{ .x = p.x, .y = p.y, .z = p.z, .t = p.t };
    const d = point.dbl();
    return .{ .x = d.x, .y = d.y, .z = d.z, .t = d.t };
}

/// Signed radix-16 digits, each in [-8, 8]. Requires s[31] <= 127.
fn radix16(s: [32]u8) [64]i32 {
    var e: [64]i32 = undefined;
    for (0..32) |i| {
        e[2 * i] = s[i] & 15;
        e[2 * i + 1] = s[i] >> 4;
    }
    var carry: i32 = 0;
    for (0..63) |i| {
        e[i] += carry;
        carry = (e[i] + 8) >> 4;
        e[i] -= carry << 4;
    }
    e[63] += carry;
    return e;
}

fn scalarmultBase(table: *const [32][8]Precomp, s: [32]u8) P3 {
    const e = radix16(s);
    var h = P3.identity;
    var i: usize = 1;
    while (i < 64) : (i += 2) {
        h = madd(h, select(table, i / 2, e[i]));
    }
    h = dbl(dbl(dbl(dbl(h))));
    i = 0;
    while (i < 64) : (i += 2) {
        h = madd(h, select(table, i / 2, e[i]));
    }
    return h;
}

fn select(table: *const [32][8]Precomp, pos: usize, b: i32) Precomp {
    if (b == 0) {
        return .{ .yplusx = Fe.one, .yminusx = Fe.one, .xy2d = Fe.zero };
    }
    const neg = b < 0;
    const absb: usize = @intCast(if (neg) -b else b);
    var t = table[pos][absb - 1];
    if (neg) {
        const ypx = t.yplusx;
        t.yplusx = t.yminusx;
        t.yminusx = ypx;
        t.xy2d = t.xy2d.neg();
    }
    return t;
}

fn canonicalLimbs(f: Fe) [5]u64 {
    return Fe.fromBytes(f.toBytes()).limbs;
}

fn buildTable() [32][8]Precomp {
    var table: [32][8]Precomp = undefined;
    var b = Edwards.basePoint;
    for (0..32) |i| {
        var p = b;
        for (0..8) |j| {
            table[i][j] = toPrecomp(p);
            p = p.add(b);
        }
        b = b.dbl().dbl().dbl().dbl().dbl().dbl().dbl().dbl();
    }
    return table;
}

fn check(table: *const [32][8]Precomp) !void {
    const samples = [_][32]u8{
        .{ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        .{ 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        .{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
        .{ 0xf8, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x40 },
    };
    for (samples) |s| {
        const got = scalarmultBase(table, s).toBytes();
        const expect = (try Edwards.basePoint.mul(s)).toBytes();
        if (!std.mem.eql(u8, &got, &expect)) return error.TableMismatch;
    }
}

fn writeLimbs(w: anytype, table: *const [32][8]Precomp) !void {
    var n: usize = 0;
    for (table) |row| {
        for (row) |pc| {
            const parts = [_][5]u64{
                canonicalLimbs(pc.yplusx),
                canonicalLimbs(pc.yminusx),
                canonicalLimbs(pc.xy2d),
            };
            for (parts) |limbs| {
                for (limbs) |limb| {
                    if (n != 0) {
                        if (n % 8 == 0) try w.writeAll(",\n") else try w.writeAll(", ");
                    }
                    try w.print("0x{x}L", .{limb});
                    n += 1;
                }
            }
        }
    }
    try w.writeAll("\n");
}

fn splice(allocator: std.mem.Allocator, path: []const u8, body: []const u8) !void {
    const src = try std.fs.cwd().readFileAlloc(allocator, path, 8 << 20);
    defer allocator.free(src);
    const start_mark = "// BASE_PRECOMP_START\n";
    const end_mark = "// BASE_PRECOMP_END\n";
    const start = std.mem.indexOf(u8, src, start_mark) orelse return error.MissingMarker;
    const end_rel = std.mem.indexOf(u8, src[start + start_mark.len ..], end_mark) orelse return error.MissingMarker;
    const end = start + start_mark.len + end_rel;

    var out: std.array_list.Managed(u8) = .init(allocator);
    defer out.deinit();
    try out.appendSlice(src[0 .. start + start_mark.len]);
    try out.appendSlice(body);
    try out.appendSlice(src[end..]);

    const file = try std.fs.cwd().createFile(path, .{});
    defer file.close();
    try file.writeAll(out.items);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const table = buildTable();
    try check(&table);
    std.debug.print("fixed-base table matches std.crypto on {d} scalars\n", .{4});

    var body: std.array_list.Managed(u8) = .init(allocator);
    defer body.deinit();
    try writeLimbs(body.writer(), &table);

    try splice(allocator, "src/shaders/vanity.metal", body.items);
    try writeZigTable(allocator, &table);
    std.debug.print("wrote {d} limbs into the Metal shader and src/base_precomp.zig\n", .{32 * 8 * 3 * 5});
}

fn writeZigTable(allocator: std.mem.Allocator, table: *const [32][8]Precomp) !void {
    var body: std.array_list.Managed(u8) = .init(allocator);
    defer body.deinit();
    const w = body.writer();
    try w.writeAll("// Generated by tools/gen_base_table.zig. Do not edit.\n");
    try w.writeAll("pub const limbs = [3840]i64{\n");
    var n: usize = 0;
    for (table) |row| {
        for (row) |pc| {
            const parts = [_][5]u64{
                canonicalLimbs(pc.yplusx),
                canonicalLimbs(pc.yminusx),
                canonicalLimbs(pc.xy2d),
            };
            for (parts) |limbs| {
                for (limbs) |limb| {
                    if (n % 8 == 0) try w.writeAll("    ");
                    try w.print("0x{x}", .{limb});
                    n += 1;
                    if (n != 3840) {
                        if (n % 8 == 0) try w.writeAll(",\n") else try w.writeAll(", ");
                    }
                }
            }
        }
    }
    try w.writeAll("\n};\n");
    const file = try std.fs.cwd().createFile("src/base_precomp.zig", .{});
    defer file.close();
    try file.writeAll(body.items);
}
