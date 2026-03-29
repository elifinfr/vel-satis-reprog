import struct

with open("firmware_ewr20.bin", "rb") as f:
    data = f.read()

BASE = 0x400

print("=== Refs IIC (I2C) registers in literal pools ===")
iic_refs = []
for off in range(0, len(data)-1, 2):
    w = struct.unpack_from('>H', data, off)[0]
    if (w >> 12) == 0xD:
        disp = w & 0xFF
        ea = (off & ~3) + 4 + disp*4
        if 0 <= ea < len(data)-3:
            val = struct.unpack_from('>I', data, ea)[0]
            if val in (0xFFFFF73A, 0xFFFFF748, 0xFFFFF756, 0xFFFFF73C, 0xFFFFF73E):
                iic_refs.append((off+BASE, val))
                if len(iic_refs) <= 12:
                    print("  0x%08X: MOV.L @PC -> 0x%08X (IIC reg)" % (off+BASE, val))

print("Total refs IIC: %d" % len(iic_refs))

print("\n=== Refs SCI2 registers in literal pools ===")
sci_refs = []
for off in range(0, len(data)-1, 2):
    w = struct.unpack_from('>H', data, off)[0]
    if (w >> 12) == 0xD:
        disp = w & 0xFF
        ea = (off & ~3) + 4 + disp*4
        if 0 <= ea < len(data)-3:
            val = struct.unpack_from('>I', data, ea)[0]
            if 0xFFFFE840 <= val <= 0xFFFFE850:
                sci_refs.append((off+BASE, val))
                if len(sci_refs) <= 12:
                    print("  0x%08X: MOV.L @PC -> 0x%08X (SCI2 reg)" % (off+BASE, val))

print("Total refs SCI2: %d" % len(sci_refs))

# Check half-word IIC references (MOV.W @PC loading 0xF73A etc)
print("\n=== Refs IIC via MOV.W (16-bit) ===")
iic16 = []
for off in range(0, len(data)-1, 2):
    w = struct.unpack_from('>H', data, off)[0]
    if (w >> 12) == 0x9:
        disp = w & 0xFF
        ea = off + BASE + 4 + disp*2
        ea_off = ea - BASE
        if 0 <= ea_off < len(data)-1:
            val = struct.unpack_from('>H', data, ea_off)[0]
            if val in (0xF73A, 0xF73C, 0xF748, 0xF756, 0xF010):
                iic16.append((off+BASE, val, ea))
                if len(iic16) <= 12:
                    print("  0x%08X: MOV.W @PC -> 0x%04X (IIC half addr)" % (off+BASE, val))

print("Total IIC MOV.W: %d" % len(iic16))

print("\n=== Address space check ===")
print("  93C66: 512 bytes max (0x000-0x1FF in 8-bit mode)")
print("  24C64: 8192 bytes   (0x0000-0x1FFF)")
print("  EEPROM[0x1FFF] used in sub_27C80:")
print("  -> 0x1FFF = 8191 = fits 24C64 exactly, IMPOSSIBLE on 93C66")

# Show 0x1FFF refs
print("\n=== 0x1FFF references (MOV.W @PC) ===")
target = b'\x1f\xff'
off = 0
while True:
    pos = data.find(target, off)
    if pos < 0: break
    addr = pos + BASE
    for lb in range(2, 200, 2):
        loff = pos - lb
        if loff < 0: break
        w2 = struct.unpack_from('>H', data, loff)[0]
        if (w2>>12) == 0x9:
            disp = w2 & 0xFF
            ea = loff + BASE + 4 + disp*2
            if ea == addr:
                print("  0x%08X: MOV.W @PC+%d,R%d -> [0x%08X]=0x1FFF" % (
                    loff+BASE, disp*2, (w2>>8)&0xF, addr))
    off = pos + 2

# Check sub_6F0E8 literal pool for IIC register
print("\n=== sub_6F0E8 literal pool (EEPROM read driver) ===")
for addr in range(0x6ECA0, 0x6ED20, 4):
    off = addr - BASE
    if 0 <= off < len(data)-3:
        val = struct.unpack_from('>I', data, off)[0]
        print("  [0x%08X] = 0x%08X" % (addr, val))
