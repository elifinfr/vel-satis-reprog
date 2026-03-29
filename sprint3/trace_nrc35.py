import struct

with open("firmware_ewr20.bin", "rb") as f:
    data = f.read()

BASE = 0x400

def read16(addr):
    off = addr - BASE
    return struct.unpack_from('>H', data, off)[0]

def read32(addr):
    off = addr - BASE
    return struct.unpack_from('>I', data, off)[0]

def disasm(start, count, label=''):
    print(f"\n=== {label} @ 0x{start:08X} ===")
    addr = start
    for _ in range(count):
        off = addr - BASE
        if off < 0 or off+2 > len(data):
            break
        w = read16(addr)
        n  = (w >> 8) & 0xF
        m  = (w >> 4) & 0xF
        d8 = w & 0xFF

        mn = f"  0x{addr:08X}: {w:04X}  "

        top4 = w >> 12
        if w == 0x000B or w == 0x0009:
            mn += "NOP" if w==0x0009 else "RTS"
        elif top4 == 0xE:
            val = d8 if d8 < 128 else d8-256
            mn += f"MOV  #{val},R{n}"
        elif top4 == 0x9:
            disp = d8
            ea = (addr & 0xFFFFFFFC) + 4 + disp*2
            val = read16(ea)
            mn += f"MOV.W @(PC+{disp*2}),R{n} ;[0x{ea:08X}]=0x{val:04X}"
        elif top4 == 0xD:
            disp = d8
            ea = (addr & 0xFFFFFFFC) + 4 + disp*4
            val = read32(ea)
            mn += f"MOV.L @(PC+{disp*4}),R{n} ;[0x{ea:08X}]=0x{val:08X}"
        elif top4 == 0x6:
            ops = {0:'MOV.B @R%m,R%n',1:'MOV.W @R%m,R%n',2:'MOV.L @R%m,R%n',
                   3:'MOV R%m,R%n',4:'MOV.B @R%m+,R%n',5:'MOV.W @R%m+,R%n',
                   6:'MOV.L @R%m+,R%n',7:'NOT R%m,R%n',
                   0xC:'EXTU.B R%m,R%n',0xD:'EXTU.W R%m,R%n',
                   0xE:'EXTS.B R%m,R%n',0xF:'EXTS.W R%m,R%n'}
            sub = w & 0xF
            s = ops.get(sub, f"0x{w:04X}")
            mn += s.replace('%m',str(m)).replace('%n',str(n))
        elif top4 == 0x2:
            ops = {0:'MOV.B R%m,@R%n',1:'MOV.W R%m,@R%n',2:'MOV.L R%m,@R%n',
                   4:'MOV.B R%m,@-R%n',5:'MOV.W R%m,@-R%n',6:'MOV.L R%m,@-R%n',
                   8:'TST R%m,R%n',9:'AND R%m,R%n',0xA:'XOR R%m,R%n',0xB:'OR R%m,R%n'}
            sub = w & 0xF
            s = ops.get(sub, f"0x{w:04X}")
            mn += s.replace('%m',str(m)).replace('%n',str(n))
        elif top4 == 0x3:
            ops = {0:'CMP/EQ R%m,R%n',2:'CMP/HS R%m,R%n',3:'CMP/GE R%m,R%n',
                   6:'CMP/HI R%m,R%n',7:'CMP/GT R%m,R%n',
                   8:'SUB R%m,R%n',0xC:'ADD R%m,R%n'}
            sub = w & 0xF
            s = ops.get(sub, f"0x{w:04X}")
            mn += s.replace('%m',str(m)).replace('%n',str(n))
        elif top4 == 0x4:
            sub = w & 0xFF
            ops4 = {0x00:f'SHLL R{n}',0x01:f'SHLR R{n}',0x08:f'SHLL2 R{n}',
                    0x09:f'SHLR2 R{n}',0x18:f'SHLL8 R{n}',0x19:f'SHLR8 R{n}',
                    0x28:f'SHLL16 R{n}',0x29:f'SHLR16 R{n}',
                    0x0B:f'JSR @R{n}',0x2B:f'JMP @R{n}',
                    0x10:f'DT R{n}',0x11:f'CMP/PZ R{n}',0x15:f'CMP/PL R{n}',
                    0x1A:f'LDS R{n},PR',0x2A:f'LDS R{n},PR',
                    0x22:f'STS.L PR,@-R{n}',0x26:f'LDS.L @R{n}+,PR',
                    0x0E:f'LDC R{n},SR',0x13:f'STC SR,R{n}',
                    0x1E:f'LDC R{n},GBR',0x12:f'STC GBR,R{n}',
                    0x1B:f'TAS.B @R{n}'}
            mn += ops4.get(sub, f"0x{w:04X}")
        elif top4 == 0x8:
            sub8 = (w >> 8) & 0xF
            disp = w & 0xFF
            if sub8 == 0x8:
                mn += f"CMP/EQ #{disp},R0"
            elif sub8 == 0xB:
                d = disp if disp < 128 else disp-256
                mn += f"BF   0x{addr+4+d*2:08X}"
            elif sub8 == 0x9:
                d = disp if disp < 128 else disp-256
                mn += f"BT   0x{addr+4+d*2:08X}"
            elif sub8 == 0xF:
                d = disp if disp < 128 else disp-256
                mn += f"BF/S 0x{addr+4+d*2:08X}"
            elif sub8 == 0xD:
                d = disp if disp < 128 else disp-256
                mn += f"BT/S 0x{addr+4+d*2:08X}"
            elif sub8 == 0x0:
                mn += f"MOV.B R0,@({disp},R{m})"
            elif sub8 == 0x1:
                mn += f"MOV.W R0,@({disp*2},R{m})"
            elif sub8 == 0x4:
                mn += f"MOV.B @({disp},R{m}),R0"
            elif sub8 == 0x5:
                mn += f"MOV.W @({disp*2},R{m}),R0"
            else:
                mn += f"0x{w:04X}"
        elif top4 == 0xA:
            disp = w & 0xFFF
            if disp & 0x800: disp |= 0xFFFFF000
            mn += f"BRA  0x{addr+4+disp*2:08X}"
        elif top4 == 0xB:
            disp = w & 0xFFF
            if disp & 0x800: disp |= 0xFFFFF000
            mn += f"BSR  0x{addr+4+disp*2:08X}"
        elif top4 == 0x7:
            val = d8 if d8 < 128 else d8-256
            mn += f"ADD  #{val},R{n}"
        elif top4 == 0x5:
            mn += f"MOV.L @({(w&0xF)*4},R{m}),R{n}"
        elif top4 == 0x1:
            mn += f"MOV.L R{m},@({(w&0xF)*4},R{n})"
        elif top4 == 0xC:
            sub = (w >> 8) & 0xF
            disp = w & 0xFF
            if sub == 4: mn += f"MOV.B @({disp},GBR),R0"
            elif sub == 5: mn += f"MOV.W @(0x{disp*2:X},GBR),R0"
            elif sub == 6: mn += f"MOV.L @(0x{disp*4:X},GBR),R0"
            elif sub == 0: mn += f"MOV.B R0,@({disp},GBR)"
            elif sub == 1: mn += f"MOV.W R0,@({disp*2},GBR)"
            elif sub == 2: mn += f"MOV.L R0,@({disp*4},GBR)"
            elif sub == 7: mn += f"MOVA @({disp*4},PC),R0 ;EA=0x{((addr&0xFFFFFFFC)+4+disp*4):08X}"
            elif sub == 8: mn += f"TST #{disp},R0"
            elif sub == 9: mn += f"AND #{disp},R0"
            elif sub == 0xA: mn += f"XOR #{disp},R0"
            elif sub == 0xB: mn += f"OR  #{disp},R0"
            elif sub == 0xD: mn += f"MOV.W @(0x{disp*2:X},GBR),R0"
            elif sub == 0xE: mn += f"MOV.L @(0x{disp*4:X},GBR),R0"
            else: mn += f"0x{w:04X}"
        elif top4 == 0x0:
            sub = w & 0xFF
            if sub == 0x0B: mn += "RTS"
            elif sub == 0x09: mn += "NOP"
            elif sub == 0x2B: mn += "RTE"
            elif sub == 0x08: mn += "CLRT"
            elif sub == 0x28: mn += "CLRMAC"
            elif sub == 0x0A: mn += f"STS MACH,R{n}"
            elif sub == 0x1A: mn += f"STS MACL,R{n}"
            elif sub == 0x2A: mn += f"STS PR,R{n}"
            elif sub == 0x02: mn += f"STC SR,R{n}"
            elif sub == 0x12: mn += f"STC GBR,R{n}"
            elif sub == 0x22: mn += f"STC VBR,R{n}"
            elif (w & 0xF) == 0x4: mn += f"MOV.B @(R0,R{m}),R{n}"
            elif (w & 0xF) == 0x5: mn += f"MOV.W @(R0,R{m}),R{n}"
            elif (w & 0xF) == 0x6: mn += f"MOV.L @(R0,R{m}),R{n}"
            elif (w & 0xF) == 0x4 and n==0: mn += f"MOV.B @(R0,R{m}),R0"
            else: mn += f"0x{w:04X}"
        else:
            mn += f"0x{w:04X}"

        print(mn)
        addr += 2

# ─── sub_27C80 — SecurityAccess handler ──────────────────────────────────────
disasm(0x27C80, 220, 'sub_27C80 (SecurityAccess main handler)')

# ─── sub_6F0E8 — EEPROM read function (to confirm what it returns for 0x1FFF) ─
disasm(0x6F0E8, 60, 'sub_6F0E8 (EEPROM read)')

# ─── scan for NRC 0x35 (MOV #0x35,Rn or CMP/EQ #0x35) ─────────────────────
print("\n=== Scan for NRC 0x35 encoding in 0x27000-0x28500 ===")
for off in range(0x27000-BASE, 0x28500-BASE, 2):
    if off+2 > len(data): break
    w = struct.unpack_from('>H', data, off)[0]
    addr = off + BASE
    # MOV #0x35,Rn  = 0xE_35  (top4=E, imm=0x35)
    if (w >> 8) == 0xE3 and (w & 0xFF) == 0x35:
        print(f"  0x{addr:08X}: {w:04X}  MOV #0x35,R{(w>>8)&0xF}")
    # also E035, E135, E235...
    if (w & 0xFF) == 0x35 and (w >> 12) == 0xE:
        print(f"  0x{addr:08X}: {w:04X}  MOV #53,R{(w>>8)&0xF}")
    # CMP/EQ #0x35,R0
    if w == 0x8835:
        print(f"  0x{addr:08X}: {w:04X}  CMP/EQ #0x35,R0")
