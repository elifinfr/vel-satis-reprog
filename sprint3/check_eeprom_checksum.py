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

def disasm_range(start, count, label=''):
    print("\n=== %s @ 0x%08X ===" % (label, start))
    addr = start
    for _ in range(count):
        off = addr - BASE
        if off < 0 or off+2 > len(data): break
        w = read16(addr)
        n  = (w >> 8) & 0xF
        m  = (w >> 4) & 0xF
        d8 = w & 0xFF
        mn = "  0x%08X: %04X  " % (addr, w)

        top4 = w >> 12
        if w == 0x000B or w == 0x0009:
            mn += "NOP" if w==0x0009 else "RTS"
        elif top4 == 0xE:
            val = d8 if d8 < 128 else d8-256
            mn += "MOV  #%d,R%d" % (val, n)
        elif top4 == 0x9:
            ea = addr+4+d8*2
            val = read16(ea)
            mn += "MOV.W @(PC+%d),R%d ;[0x%08X]=0x%04X" % (d8*2, n, ea, val)
        elif top4 == 0xD:
            ea = (addr & ~3)+4+d8*4
            val = read32(ea)
            mn += "MOV.L @(PC+%d),R%d ;[0x%08X]=0x%08X" % (d8*4, n, ea, val)
        elif top4 == 0x6:
            ops = {0:'MOV.B @R%m,R%n',1:'MOV.W @R%m,R%n',2:'MOV.L @R%m,R%n',
                   3:'MOV R%m,R%n',4:'MOV.B @R%m+,R%n',5:'MOV.W @R%m+,R%n',
                   6:'MOV.L @R%m+,R%n',7:'NOT R%m,R%n',
                   0xC:'EXTU.B R%m,R%n',0xD:'EXTU.W R%m,R%n',
                   0xE:'EXTS.B R%m,R%n',0xF:'EXTS.W R%m,R%n'}
            sub = w & 0xF
            s = ops.get(sub, "0x%04X" % w)
            mn += s.replace('%m',str(m)).replace('%n',str(n))
        elif top4 == 0x2:
            ops = {0:'MOV.B R%m,@R%n',1:'MOV.W R%m,@R%n',2:'MOV.L R%m,@R%n',
                   4:'MOV.B R%m,@-R%n',5:'MOV.W R%m,@-R%n',6:'MOV.L R%m,@-R%n',
                   8:'TST R%m,R%n',9:'AND R%m,R%n',0xA:'XOR R%m,R%n',0xB:'OR R%m,R%n'}
            sub = w & 0xF
            s = ops.get(sub, "0x%04X" % w)
            mn += s.replace('%m',str(m)).replace('%n',str(n))
        elif top4 == 0x3:
            ops = {0:'CMP/EQ R%m,R%n',2:'CMP/HS R%m,R%n',3:'CMP/GE R%m,R%n',
                   6:'CMP/HI R%m,R%n',7:'CMP/GT R%m,R%n',
                   8:'SUB R%m,R%n',0xC:'ADD R%m,R%n',0xE:'ADDC R%m,R%n'}
            sub = w & 0xF
            s = ops.get(sub, "0x%04X" % w)
            mn += s.replace('%m',str(m)).replace('%n',str(n))
        elif top4 == 0x4:
            sub = w & 0xFF
            ops4 = {0x00:'SHLL R%n',0x01:'SHLR R%n',0x08:'SHLL2 R%n',
                    0x09:'SHLR2 R%n',0x18:'SHLL8 R%n',0x19:'SHLR8 R%n',
                    0x28:'SHLL16 R%n',0x29:'SHLR16 R%n',
                    0x0B:'JSR @R%n',0x2B:'JMP @R%n',
                    0x10:'DT R%n',0x11:'CMP/PZ R%n',0x15:'CMP/PL R%n',
                    0x1A:'LDS R%n,PR',0x2A:'LDS R%n,PR',
                    0x22:'STS.L PR,@-R%n',0x26:'LDS.L @R%n+,PR',
                    0x1E:'LDC R%n,GBR',0x13:'STC SR,R%n',
                    0x1B:'TAS.B @R%n'}
            s = ops4.get(sub, "0x%04X" % w)
            mn += s.replace('%n',str(n)).replace('%m',str(m))
        elif top4 == 0x8:
            sub8 = (w >> 8) & 0xF
            disp = w & 0xFF
            if sub8 == 0x8:
                mn += "CMP/EQ #%d,R0" % disp
            elif sub8 == 0xB:
                d = disp if disp < 128 else disp-256
                mn += "BF   0x%08X" % (addr+4+d*2)
            elif sub8 == 0x9:
                d = disp if disp < 128 else disp-256
                mn += "BT   0x%08X" % (addr+4+d*2)
            elif sub8 == 0xF:
                d = disp if disp < 128 else disp-256
                mn += "BF/S 0x%08X" % (addr+4+d*2)
            elif sub8 == 0xD:
                d = disp if disp < 128 else disp-256
                mn += "BT/S 0x%08X" % (addr+4+d*2)
            elif sub8 == 0x0: mn += "MOV.B R0,@(%d,R%d)" % (disp, (w>>4)&0xF)
            elif sub8 == 0x1: mn += "MOV.W R0,@(%d,R%d)" % (disp*2, (w>>4)&0xF)
            elif sub8 == 0x4: mn += "MOV.B @(%d,R%d),R0" % (disp, (w>>4)&0xF)
            elif sub8 == 0x5: mn += "MOV.W @(%d,R%d),R0" % (disp*2, (w>>4)&0xF)
            else: mn += "0x%04X" % w
        elif top4 == 0xA:
            disp = w & 0xFFF
            if disp & 0x800: disp |= 0xFFFFF000
            mn += "BRA  0x%08X" % ((addr+4+disp*2) & 0xFFFFFFFF)
        elif top4 == 0xB:
            disp = w & 0xFFF
            if disp & 0x800: disp |= 0xFFFFF000
            mn += "BSR  0x%08X" % ((addr+4+disp*2) & 0xFFFFFFFF)
        elif top4 == 0x7:
            val = d8 if d8 < 128 else d8-256
            mn += "ADD  #%d,R%d" % (val, n)
        elif top4 == 0x5:
            mn += "MOV.L @(%d,R%d),R%d" % ((w&0xF)*4, m, n)
        elif top4 == 0x1:
            mn += "MOV.L R%d,@(%d,R%d)" % (n, (w&0xF)*4, m)
        elif top4 == 0xC:
            sub = (w >> 8) & 0xF
            disp = w & 0xFF
            if sub == 4: mn += "MOV.B @(%d,GBR),R0" % disp
            elif sub == 5: mn += "MOV.W @(0x%X,GBR),R0" % (disp*2)
            elif sub == 6: mn += "MOV.L @(0x%X,GBR),R0" % (disp*4)
            elif sub == 0: mn += "MOV.B R0,@(%d,GBR)" % disp
            elif sub == 1: mn += "MOV.W R0,@(%d,GBR)" % (disp*2)
            elif sub == 2: mn += "MOV.L R0,@(%d,GBR)" % (disp*4)
            elif sub == 7: mn += "MOVA @(%d,PC),R0 ;EA=0x%08X" % (disp*4, ((addr&~3)+4+disp*4))
            elif sub == 8: mn += "TST #%d,R0" % disp
            elif sub == 9: mn += "AND #0x%02X,R0" % disp
            elif sub == 0xA: mn += "XOR #0x%02X,R0" % disp
            elif sub == 0xB: mn += "OR  #0x%02X,R0" % disp
            else: mn += "0x%04X" % w
        elif top4 == 0x0:
            sub = w & 0xFF
            if sub == 0x0B: mn += "RTS"
            elif sub == 0x09: mn += "NOP"
            elif sub == 0x2B: mn += "RTE"
            elif sub == 0x08: mn += "CLRT"
            elif sub == 0x28: mn += "CLRMAC"
            elif sub == 0x0A: mn += "STS MACH,R%d" % n
            elif sub == 0x1A: mn += "STS MACL,R%d" % n
            elif sub == 0x2A: mn += "STS PR,R%d" % n
            elif sub == 0x02: mn += "STC SR,R%d" % n
            elif sub == 0x12: mn += "STC GBR,R%d" % n
            elif sub == 0x22: mn += "STC VBR,R%d" % n
            elif (w & 0xF) == 0x4: mn += "MOV.B @(R0,R%d),R%d" % (m, n)
            elif (w & 0xF) == 0x5: mn += "MOV.W @(R0,R%d),R%d" % (m, n)
            elif (w & 0xF) == 0x6: mn += "MOV.L @(R0,R%d),R%d" % (m, n)
            else: mn += "0x%04X" % w
        else:
            mn += "0x%04X" % w

        print(mn)
        addr += 2
        if mn.strip().endswith("RTS"):
            break


# ─── 1. Chercher les fonctions qui calculent un checksum sur l'EEPROM ──────
# Pattern typique: boucle de lecture EEPROM + ADD ou XOR sur tous les octets
# Chercher CMP/EQ sur résultat de somme, ou des appels à sub_6F0E8/sub_6F61C
# dans une boucle (DT = décrement et test = boucle)

print("=== Recherche boucles checksum EEPROM (DT Rn + appel read) ===")
# DT = opcode 0x4_10
dt_addrs = []
for off in range(0, len(data)-1, 2):
    w = struct.unpack_from('>H', data, off)[0]
    # DT Rn = 0x4n10
    if (w & 0xFF0F) == 0x4010 and (w >> 12) == 0x4:
        dt_addrs.append(off + BASE)

print("Toutes les instructions DT (dec+test, typique boucle): %d occurrences" % len(dt_addrs))
# On cherche DT proches d'un JSR vers sub_6F0E8 (0x6F0E8) ou sub_6F61C (0x6F61C)
eeprom_read_addrs = {0x6F0E8, 0x6F61C}

for dt_addr in dt_addrs:
    # Regarder dans un rayon de +/-60 instructions
    for scan_off in range(dt_addr - BASE - 120, dt_addr - BASE + 120, 2):
        if scan_off < 0 or scan_off >= len(data)-1: continue
        sw = struct.unpack_from('>H', data, scan_off)[0]
        # MOV.L @PC chargeant une adresse EEPROM read func
        if (sw >> 12) == 0xD:
            disp = sw & 0xFF
            ea = (scan_off & ~3) + 4 + disp*4
            if 0 <= ea < len(data)-3:
                val = struct.unpack_from('>I', data, ea)[0]
                if val in eeprom_read_addrs:
                    print("  DT @ 0x%08X + EEPROM read call nearby (func=0x%08X)" % (dt_addr, val))
                    break

# ─── 2. Chercher les fonctions de vérification checksum EEPROM au démarrage ─
# L'état 2 du state machine K-Line (0xCA098) fait "EEPROM checksum"
# Chercher sub appelée depuis 0xCA098 avant sub_27C80

print("\n=== State machine K-Line @ 0xCA098 — etat 2 (EEPROM checksum) ===")
disasm_range(0xCA098, 80, "K-Line state machine début")

# ─── 3. La fonction sub_6E874 (état 3) ──────────────────────────────────────
# Si sub_6E874 calcule un checksum EEPROM, les 4 adresses qu'on veut modifier
# sont-elles dans la plage checksum?
print("\n=== sub_6E874 (etat 3 du state machine) ===")
disasm_range(0x6E874, 60, "sub_6E874")

# ─── 4. Chercher explicitement les fonctions checksum EEPROM ────────────────
# Pattern: lire N octets EEPROM, sommer, comparer à un octet de référence
# L'octet de checksum est souvent stocké dans l'EEPROM elle-même
# Chercher des séquences: call sub_6F0E8, ADD R0,Rn, boucle DT

print("\n=== Scan: appels sub_6F0E8 dans des boucles (candidats checksum) ===")
# Chercher les call sites de sub_6F0E8 (0x6F0E8)
func_read = 0x6F0E8
call_sites_read = []
for off in range(0, len(data)-1, 2):
    w = struct.unpack_from('>H', data, off)[0]
    if (w >> 12) == 0xD:
        disp = w & 0xFF
        ea = (off & ~3) + 4 + disp*4
        if 0 <= ea < len(data)-3:
            val = struct.unpack_from('>I', data, ea)[0]
            if val == func_read:
                call_sites_read.append(off + BASE)

print("Call sites sub_6F0E8: %d" % len(call_sites_read))
for cs in call_sites_read[:20]:
    # Chercher DT dans un rayon de 40 instr autour
    found_dt = False
    for scan_off in range(cs - BASE - 80, cs - BASE + 80, 2):
        if scan_off < 0: continue
        sw = struct.unpack_from('>H', data, scan_off)[0]
        if (sw & 0xFF0F) == 0x4010 and (sw >> 12) == 0x4:
            found_dt = True
            break
    loop_flag = " [BOUCLE DT - candidat checksum!]" if found_dt else ""
    print("  0x%08X%s" % (cs, loop_flag))

# ─── 5. Chercher les patterns ADD dans les boucles de lecture EEPROM ────────
print("\n=== Fonctions avec DT + ADD (accumulation checksum) ===")
# DT + ADD Rm,Rn dans un rayon de 30 instr
for dt_addr in dt_addrs:
    dt_off = dt_addr - BASE
    found_add = False
    for scan_off in range(dt_off - 60, dt_off + 4, 2):
        if scan_off < 0: continue
        sw = struct.unpack_from('>H', data, scan_off)[0]
        if (sw >> 12) == 0x3 and (sw & 0xF) == 0xC:  # ADD Rm,Rn
            found_add = True
            break
    if found_add:
        # Y a-t-il un call EEPROM read?
        has_eeprom = False
        for scan_off in range(dt_off - 160, dt_off + 4, 2):
            if scan_off < 0: continue
            sw = struct.unpack_from('>H', data, scan_off)[0]
            if (sw >> 12) == 0xD:
                disp2 = sw & 0xFF
                ea2 = (scan_off & ~3) + 4 + disp2*4
                if 0 <= ea2 < len(data)-3:
                    val2 = struct.unpack_from('>I', data, ea2)[0]
                    if val2 in (0x6F0E8, 0x6F61C, 0x6EBD8, 0x6ED78):
                        has_eeprom = True
                        break
        if has_eeprom:
            print("  DT @ 0x%08X  avec ADD + appel EEPROM [CHECKSUM PROBABLE]" % dt_addr)

# ─── 6. Vérifier quelles adresses EEPROM sont lues en dehors du path 0x27 ──
# Si checksum ne couvre pas 0x1FFF-0x1FF0, on est safe
print("\n=== Plages EEPROM lues par adresse (hors sub_27C80) ===")
# Chercher tous les MOV.W @PC chargeant des valeurs 0x1FXX
for off in range(0, len(data)-1, 2):
    w = struct.unpack_from('>H', data, off)[0]
    if (w >> 12) == 0x9:
        disp = w & 0xFF
        ea = off + BASE + 4 + disp*2
        ea_off = ea - BASE
        if 0 <= ea_off < len(data)-1:
            val = struct.unpack_from('>H', data, ea_off)[0]
            if 0x1F00 <= val <= 0x1FFF:
                print("  0x%08X: charge EEPROM addr 0x%04X en R%d" % (off+BASE, val, (w>>8)&0xF))
