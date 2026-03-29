#!/usr/bin/env python3
"""
Analyse ciblée : sub_28470 (compteur EEPROM), sub_6ED78 (write suite),
sub_6F61C (suite), et recherche des appels write EEPROM avec index 0x1FFF
"""
import struct, sys

FW_PATH = "E:/7058/firmware_ewr20.bin"
BASE = 0x400

with open(FW_PATH, 'rb') as f:
    fw = f.read()

def fw_u16(addr):
    off = addr - BASE
    if 0 <= off < len(fw)-1:
        return struct.unpack_from('>H', fw, off)[0]
    return 0xFFFF

def fw_u32(addr):
    off = addr - BASE
    if 0 <= off < len(fw)-3:
        return struct.unpack_from('>I', fw, off)[0]
    return 0xFFFFFFFF

def sh2_one(pc):
    w = fw_u16(pc)
    hi = (w >> 12) & 0xF
    nn = (w >> 8) & 0xF  # destination reg (bits 11-8)
    mm = (w >> 4) & 0xF  # source reg (bits 7-4)
    d  =  w & 0xF
    imm8 = w & 0xFF

    # BRA/BSR
    if hi == 0xA:
        disp = w & 0xFFF
        if disp & 0x800: disp |= 0xFFFFF000
        return f'BRA  0x{(pc+4+disp*2)&0xFFFFFFFF:08X}', pc+2
    if hi == 0xB:
        disp = w & 0xFFF
        if disp & 0x800: disp |= 0xFFFFF000
        return f'BSR  0x{(pc+4+disp*2)&0xFFFFFFFF:08X}', pc+2

    # BT/BF/BT.S/BF.S
    for code, mnem in [(0x89,'BT  '), (0x8B,'BF  '), (0x8D,'BT/S'), (0x8F,'BF/S')]:
        if (w >> 8) == code:
            disp = imm8
            if disp & 0x80: disp |= 0xFFFFFF00
            return f'{mnem} 0x{(pc+4+disp*2)&0xFFFFFFFF:08X}', pc+2

    # MOV.L @(d,PC),Rn
    if hi == 0xD:
        target = (pc & ~3) + 4 + (imm8)*4
        val = fw_u32(target)
        return f'MOV.L @(PC+{imm8*4}),R{nn}  ; [0x{target:08X}]=0x{val:08X}', pc+2

    # MOV.W @(d,PC),Rn
    if hi == 0x9:
        target = pc + 4 + imm8*2
        val = fw_u16(target)
        return f'MOV.W @(PC+{imm8*2}),R{nn}  ; [0x{target:08X}]=0x{val:04X}', pc+2

    # MOV #imm,Rn
    if hi == 0xE:
        imm = imm8; imm = imm | 0xFFFFFF00 if imm & 0x80 else imm
        return f'MOV  #0x{imm&0xFF:02X},R{nn}', pc+2

    # ADD #imm,Rn
    if hi == 0x7:
        imm = imm8; imm = imm | 0xFFFFFF00 if imm & 0x80 else imm
        return f'ADD  #0x{imm&0xFF:02X},R{nn}', pc+2

    # MOV.L Rm,@-Rn (push)
    if hi == 0x2 and d == 6:
        return f'MOV.L R{mm},@-R{nn}', pc+2
    if hi == 0x2 and d == 5:
        return f'MOV.W R{mm},@-R{nn}', pc+2
    if hi == 0x2 and d == 4:
        return f'MOV.B R{mm},@-R{nn}', pc+2
    if hi == 0x2 and d == 2:
        return f'MOV.L R{mm},@R{nn}', pc+2
    if hi == 0x2 and d == 1:
        return f'MOV.W R{mm},@R{nn}', pc+2
    if hi == 0x2 and d == 0:
        return f'MOV.B R{mm},@R{nn}', pc+2

    # 2nm7 = DIV0S, 2nm8=TST, 2nm9=AND, 2nmA=XOR, 2nmB=OR
    if hi == 0x2 and d == 8:
        return f'TST  R{mm},R{nn}', pc+2
    if hi == 0x2 and d == 9:
        return f'AND  R{mm},R{nn}', pc+2
    if hi == 0x2 and d == 0xA:
        return f'XOR  R{mm},R{nn}', pc+2
    if hi == 0x2 and d == 0xB:
        return f'OR   R{mm},R{nn}', pc+2
    if hi == 0x2 and d == 0xE:
        return f'MULS.W R{mm},R{nn}', pc+2
    if hi == 0x2 and d == 0xF:
        return f'MULU.W R{mm},R{nn}', pc+2
    if hi == 0x2 and d == 7:
        return f'DIV0S R{mm},R{nn}', pc+2
    if hi == 0x2 and d == 0xC:
        return f'MUL.L R{mm},R{nn}', pc+2

    # MOV.L @Rm+,Rn (pop)
    if hi == 0x6 and d == 6:
        return f'MOV.L @R{mm}+,R{nn}', pc+2
    if hi == 0x6 and d == 5:
        return f'MOV.W @R{mm}+,R{nn}', pc+2
    if hi == 0x6 and d == 4:
        return f'MOV.B @R{mm}+,R{nn}', pc+2
    if hi == 0x6 and d == 2:
        return f'MOV.L @R{mm},R{nn}', pc+2
    if hi == 0x6 and d == 1:
        return f'MOV.W @R{mm},R{nn}', pc+2
    if hi == 0x6 and d == 0:
        return f'MOV.B @R{mm},R{nn}', pc+2
    if hi == 0x6 and d == 3:
        return f'MOV  R{mm},R{nn}', pc+2
    if hi == 0x6 and d == 7:
        return f'NOT  R{mm},R{nn}', pc+2
    if hi == 0x6 and d == 8:
        return f'SWAP.B R{mm},R{nn}', pc+2
    if hi == 0x6 and d == 9:
        return f'SWAP.W R{mm},R{nn}', pc+2
    if hi == 0x6 and d == 0xA:
        return f'NEGC R{mm},R{nn}', pc+2
    if hi == 0x6 and d == 0xB:
        return f'NEG  R{mm},R{nn}', pc+2
    if hi == 0x6 and d == 0xC:
        return f'EXTU.B R{mm},R{nn}', pc+2
    if hi == 0x6 and d == 0xD:
        return f'EXTU.W R{mm},R{nn}', pc+2
    if hi == 0x6 and d == 0xE:
        return f'EXTS.B R{mm},R{nn}', pc+2
    if hi == 0x6 and d == 0xF:
        return f'EXTS.W R{mm},R{nn}', pc+2

    # MOV.L Rn,@(disp,Rm)
    if hi == 0x1:
        return f'MOV.L R{nn},@(0x{d*4:X},R{mm})', pc+2
    # MOV.L @(disp,Rm),Rn
    if hi == 0x5:
        return f'MOV.L @(0x{d*4:X},R{mm}),R{nn}', pc+2

    # CMP instructions
    if hi == 0x3:
        ops = {0:'CMP/EQ',2:'CMP/HS',3:'CMP/GE',4:'DIV1',5:'DMULU.L',
               6:'CMP/HI',7:'CMP/GT',8:'SUB',0xA:'SUBC',0xB:'SUBV',
               0xC:'ADD ',0xD:'DMULS.L',0xE:'ADDC',0xF:'ADDV'}
        return f'{ops.get(d,f"3{d:X}")} R{mm},R{nn}', pc+2

    # Format 4
    if hi == 0x4:
        op_code = (mm << 4) | d
        ops4 = {
            0x00:f'SHLL R{nn}',0x01:f'SHLR R{nn}',
            0x02:f'STS.L MACH,@-R{nn}',0x04:f'ROTL R{nn}',0x05:f'ROTR R{nn}',
            0x06:f'LDS.L @R{nn}+,MACH',0x08:f'SHLL2 R{nn}',0x09:f'SHLR2 R{nn}',
            0x0A:f'LDS R{nn},MACH',0x0B:f'JSR  @R{nn}',0x0E:f'LDC R{nn},SR',
            0x0F:f'MAC.W @R{mm}+,@R{nn}+',
            0x10:f'DT   R{nn}',0x11:f'CMP/PZ R{nn}',0x15:f'CMP/PL R{nn}',
            0x16:f'LDS.L @R{nn}+,MACL',0x17:f'LDC.L @R{nn}+,GBR',
            0x18:f'SHLL8 R{nn}',0x19:f'SHLR8 R{nn}',
            0x1A:f'LDS R{nn},MACL',0x1B:f'TAS.B @R{nn}',
            0x1E:f'LDC R{nn},GBR',
            0x20:f'SHAL R{nn}',0x21:f'SHAR R{nn}',
            0x22:f'STS.L PR,@-R{nn}',0x23:f'STC.L VBR,@-R{nn}',
            0x24:f'ROTCL R{nn}',0x25:f'ROTCR R{nn}',
            0x26:f'LDS.L @R{nn}+,PR',0x27:f'LDC.L @R{nn}+,VBR',
            0x28:f'SHLL16 R{nn}',0x29:f'SHLR16 R{nn}',
            0x2A:f'LDS R{nn},PR',0x2B:f'JMP  @R{nn}',
            0x2E:f'LDC R{nn},VBR',
            0x13:f'STC.L GBR,@-R{nn}',  # SH-2A extended?
        }
        return ops4.get(op_code, f'4{nn:X}{op_code:02X}'), pc+2

    # Format 0
    if hi == 0x0:
        op = (mm << 4) | d
        # special cases
        if w == 0x0009: return 'NOP', pc+2
        if w == 0x000B: return 'RTS', pc+2
        if w == 0x002B: return 'RTE', pc+2
        if w == 0x0008: return 'CLRT', pc+2
        if w == 0x0018: return 'SETT', pc+2
        if w == 0x0019: return 'DIV0U', pc+2
        if w == 0x0028: return 'CLRMAC', pc+2
        if w == 0x001B: return 'SLEEP', pc+2
        ops0 = {
            0x02:f'STC SR,R{nn}',0x03:f'BSRF R{mm}',
            0x0A:f'STS MACH,R{nn}',0x12:f'STC GBR,R{nn}',
            0x1A:f'STS MACL,R{nn}',0x22:f'STC VBR,R{nn}',
            0x29:f'MOVT R{nn}',0x2A:f'STS PR,R{nn}',
            0x3B:f'BRAF R{mm}',
            0x04:f'MOV.B R{mm},@(R0,R{nn})',0x05:f'MOV.W R{mm},@(R0,R{nn})',
            0x06:f'MOV.L R{mm},@(R0,R{nn})',0x07:f'MUL.L R{mm},R{nn}',
            0x0C:f'MOV.B @(R0,R{mm}),R{nn}',0x0D:f'MOV.W @(R0,R{mm}),R{nn}',
            0x0E:f'MOV.L @(R0,R{mm}),R{nn}',
            0x0F:f'MAC.L @R{mm}+,@R{nn}+',
        }
        return ops0.get(op, f'0{nn:X}{mm:X}{d:X}'), pc+2

    # MOVA @(d,PC),R0
    if (w >> 8) == 0xC7:
        target = (pc & ~3) + 4 + imm8*4
        return f'MOVA @(PC+{imm8*4}),R0  ; 0x{target:08X}', pc+2

    # TST/XOR/OR/AND #imm,R0
    for code, mnem in [(0xC8,'TST #'), (0xCA,'XOR #'), (0xCB,'OR  #'), (0xC9,'AND #')]:
        if (w >> 8) == code:
            return f'{mnem}0x{imm8:02X},R0', pc+2

    # CMP/EQ #imm,R0
    if (w >> 8) == 0x88:
        imm = imm8; imm = imm | 0xFFFFFF00 if imm & 0x80 else imm
        return f'CMP/EQ #{imm&0xFF},R0  ;0x{imm&0xFF:02X}', pc+2

    # MOV.B @(d,Rm),R0 / MOV.B R0,@(d,Rm)
    if (w >> 8) == 0x80:
        return f'MOV.B R0,@(0x{(w&0xF):X},R{(w>>4)&0xF})', pc+2
    if (w >> 8) == 0x81:
        return f'MOV.W R0,@(0x{(w&0xF)*2:X},R{(w>>4)&0xF})', pc+2
    if (w >> 8) == 0x84:
        return f'MOV.B @(0x{(w&0xF):X},R{(w>>4)&0xF}),R0', pc+2
    if (w >> 8) == 0x85:
        return f'MOV.W @(0x{(w&0xF)*2:X},R{(w>>4)&0xF}),R0', pc+2

    # TRAPA
    if (w >> 8) == 0xC3:
        return f'TRAPA #{imm8}', pc+2

    # Catch-all
    return f'?{w:04X}', pc+2

def disasm(addr, n=100):
    pc = addr
    last_rts = False
    for i in range(n):
        ins, next_pc = sh2_one(pc)
        print(f'  0x{pc:08X}: {fw_u16(pc):04X}  {ins}')
        if last_rts:
            break
        if any(ins.startswith(x) for x in ['RTS','RTE','JMP ','BRA ']):
            last_rts = True
        pc = next_pc

def print_func(addr, name):
    print(f'\n{"="*68}')
    print(f'  {name}  @ 0x{addr:08X}')
    print(f'{"="*68}')
    disasm(addr, 120)

# 1. sub_28470 — ce qui se passe quand auth échoue (incrémente compteur)
print_func(0x28470, "sub_28470 — action sur auth failure (increment counter?)")

# 2. sub_2851C — vérification KEY (appelé depuis sub_283EC)
print_func(0x2851C, "sub_2851C — vérification KEY")

# 3. sub_70554 — appelé depuis sub_283EC (key verify?)
print_func(0x70554, "sub_70554 — appelé depuis sub_283EC")

# 4. Chercher les appels à sub_6ED78 (EEPROM write) avec index 0x1FFF ou 0x1FF0
print(f'\n{"="*68}')
print('  RECHERCHE: appels EEPROM write (sub_6ED78) avec index 0x1FFF/0x1FF0')
print(f'{"="*68}')

# Chercher dans le firmware les patterns qui chargent 0x1FFF puis appellent sub_6ED78
WRITE_FUNC = 0x6ED78
write_ptr_bytes = struct.pack('>I', WRITE_FUNC)

# Chercher les références à sub_6ED78 dans le firmware
print(f'\nRecherche de 0x{WRITE_FUNC:08X} dans la flash...')
off = 0
refs_write = []
while True:
    pos = fw.find(write_ptr_bytes, off)
    if pos < 0: break
    addr = pos + BASE
    refs_write.append(addr)
    print(f'  Référence à sub_6ED78 @ 0x{addr:08X} (offset 0x{pos:X})')
    off = pos + 1

# Chercher les références à sub_6F61C (EEPROM read) avec index 0x1FFF
READ_FUNC = 0x6F61C
read_ptr_bytes = struct.pack('>I', READ_FUNC)
print(f'\nRecherche de 0x{READ_FUNC:08X} dans la flash...')
refs_read = []
off = 0
while True:
    pos = fw.find(read_ptr_bytes, off)
    if pos < 0: break
    addr = pos + BASE
    refs_read.append(addr)
    print(f'  Référence à sub_6F61C @ 0x{addr:08X} (offset 0x{pos:X})')
    off = pos + 1

# Pour chaque référence à sub_6ED78, regarder le contexte (index passé dans R4)
print(f'\n--- Contexte des appels à sub_6ED78 ---')
for ref in refs_write:
    print(f'\nRéférence @ 0x{ref:08X}:')
    # Regarder les 16 octets avant la référence pour voir comment R4 est chargé
    for lookback in range(0, 64, 2):
        pc = ref - lookback
        if pc < BASE: break
        ins, _ = sh2_one(pc)
        if 'R4' in ins or 'R5' in ins or 'R6' in ins:
            print(f'    0x{pc:08X}: {ins}')

# 5. Analyser sub_2848C (calcul seed) pour comprendre les timers ATU
print_func(0x2848C, "sub_2848C — calcul seed (ATU timers)")

# 6. Analyser sub_27BD4 (KWP dispatcher principal)
print_func(0x27BD4, "sub_27BD4 — KWP dispatcher principal")
