#!/usr/bin/env python3
"""
Analyse ciblée sprint 3 :
- Contexte complet sub_283EC (counter logic)
- sub_31228 et voisins (write EEPROM calls)
- Recherche du service KWP qui écrit le compteur
- Services 0x3D, 0x3B dans le dispatcher
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
    nn = (w >> 8) & 0xF
    mm = (w >> 4) & 0xF
    d  =  w & 0xF
    imm8 = w & 0xFF

    if hi == 0xA:
        disp = w & 0xFFF
        if disp & 0x800: disp |= 0xFFFFF000
        return f'BRA  0x{(pc+4+disp*2)&0xFFFFFFFF:08X}', pc+2
    if hi == 0xB:
        disp = w & 0xFFF
        if disp & 0x800: disp |= 0xFFFFF000
        return f'BSR  0x{(pc+4+disp*2)&0xFFFFFFFF:08X}', pc+2
    for code, mnem in [(0x89,'BT  '),(0x8B,'BF  '),(0x8D,'BT/S'),(0x8F,'BF/S')]:
        if (w>>8)==code:
            disp = imm8; disp = disp|0xFFFFFF00 if disp&0x80 else disp
            return f'{mnem} 0x{(pc+4+disp*2)&0xFFFFFFFF:08X}', pc+2
    if hi==0xD:
        t=(pc&~3)+4+imm8*4; v=fw_u32(t)
        return f'MOV.L @(PC+{imm8*4}),R{nn} ;[0x{t:08X}]=0x{v:08X}', pc+2
    if hi==0x9:
        t=pc+4+imm8*2; v=fw_u16(t)
        return f'MOV.W @(PC+{imm8*2}),R{nn} ;[0x{t:08X}]=0x{v:04X}', pc+2
    if hi==0xE:
        imm=imm8; imm=imm|0xFFFFFF00 if imm&0x80 else imm
        return f'MOV  #{imm},R{nn}', pc+2
    if hi==0x7:
        imm=imm8; imm=imm|0xFFFFFF00 if imm&0x80 else imm
        return f'ADD  #{imm},R{nn}', pc+2
    if hi==0x2:
        ops={0:'MOV.B @Rm →',1:'MOV.W @Rm →',2:'MOV.L @Rm →',
             4:'MOV.B Rm→@-Rn',5:'MOV.W Rm→@-Rn',6:'MOV.L Rm→@-Rn',
             7:'DIV0S',8:'TST R,R',9:'AND R,R',0xA:'XOR R,R',0xB:'OR  R,R',
             0xC:'MUL.L',0xE:'MULS.W',0xF:'MULU.W'}
        if d==6: return f'MOV.L R{mm},@-R{nn}', pc+2
        if d==5: return f'MOV.W R{mm},@-R{nn}', pc+2
        if d==4: return f'MOV.B R{mm},@-R{nn}', pc+2
        if d==2: return f'MOV.L R{mm},@R{nn}', pc+2
        if d==1: return f'MOV.W R{mm},@R{nn}', pc+2
        if d==0: return f'MOV.B R{mm},@R{nn}', pc+2
        if d==8: return f'TST  R{mm},R{nn}', pc+2
        if d==9: return f'AND  R{mm},R{nn}', pc+2
        if d==0xA: return f'XOR  R{mm},R{nn}', pc+2
        if d==0xB: return f'OR   R{mm},R{nn}', pc+2
        if d==0xC: return f'MUL.L R{mm},R{nn}', pc+2
        if d==0xE: return f'MULS.W R{mm},R{nn}', pc+2
        if d==0xF: return f'MULU.W R{mm},R{nn}', pc+2
        if d==7: return f'DIV0S R{mm},R{nn}', pc+2
    if hi==0x6:
        if d==6: return f'MOV.L @R{mm}+,R{nn}', pc+2
        if d==5: return f'MOV.W @R{mm}+,R{nn}', pc+2
        if d==4: return f'MOV.B @R{mm}+,R{nn}', pc+2
        if d==2: return f'MOV.L @R{mm},R{nn}', pc+2
        if d==1: return f'MOV.W @R{mm},R{nn}', pc+2
        if d==0: return f'MOV.B @R{mm},R{nn}', pc+2
        if d==3: return f'MOV  R{mm},R{nn}', pc+2
        if d==7: return f'NOT  R{mm},R{nn}', pc+2
        if d==8: return f'SWAP.B R{mm},R{nn}', pc+2
        if d==9: return f'SWAP.W R{mm},R{nn}', pc+2
        if d==0xA: return f'NEGC R{mm},R{nn}', pc+2
        if d==0xB: return f'NEG  R{mm},R{nn}', pc+2
        if d==0xC: return f'EXTU.B R{mm},R{nn}', pc+2
        if d==0xD: return f'EXTU.W R{mm},R{nn}', pc+2
        if d==0xE: return f'EXTS.B R{mm},R{nn}', pc+2
        if d==0xF: return f'EXTS.W R{mm},R{nn}', pc+2
    if hi==0x1: return f'MOV.L R{nn},@(0x{d*4:X},R{mm})', pc+2
    if hi==0x5: return f'MOV.L @(0x{d*4:X},R{mm}),R{nn}', pc+2
    if hi==0x3:
        ops={0:'CMP/EQ',2:'CMP/HS',3:'CMP/GE',4:'DIV1',5:'DMULU.L',
             6:'CMP/HI',7:'CMP/GT',8:'SUB',0xA:'SUBC',0xB:'SUBV',
             0xC:'ADD ',0xD:'DMULS.L',0xE:'ADDC',0xF:'ADDV'}
        return f'{ops.get(d,f"3{d:X}")} R{mm},R{nn}', pc+2
    if hi==0x4:
        oc=(mm<<4)|d
        t4={
            0x00:f'SHLL R{nn}',0x01:f'SHLR R{nn}',0x02:f'STS.L MACH,@-R{nn}',
            0x04:f'ROTL R{nn}',0x05:f'ROTR R{nn}',0x06:f'LDS.L @R{nn}+,MACH',
            0x08:f'SHLL2 R{nn}',0x09:f'SHLR2 R{nn}',0x0A:f'LDS R{nn},MACH',
            0x0B:f'JSR  @R{nn}',0x0E:f'LDC R{nn},SR',0x0F:f'MAC.W @R{mm}+,@R{nn}+',
            0x10:f'DT   R{nn}',0x11:f'CMP/PZ R{nn}',0x15:f'CMP/PL R{nn}',
            0x16:f'LDS.L @R{nn}+,MACL',0x17:f'LDC.L @R{nn}+,GBR',
            0x18:f'SHLL8 R{nn}',0x19:f'SHLR8 R{nn}',0x1A:f'LDS R{nn},MACL',
            0x1B:f'TAS.B @R{nn}',0x1E:f'LDC R{nn},GBR',
            0x20:f'SHAL R{nn}',0x21:f'SHAR R{nn}',0x22:f'STS.L PR,@-R{nn}',
            0x23:f'STC.L VBR,@-R{nn}',0x24:f'ROTCL R{nn}',0x25:f'ROTCR R{nn}',
            0x26:f'LDS.L @R{nn}+,PR',0x27:f'LDC.L @R{nn}+,VBR',
            0x28:f'SHLL16 R{nn}',0x29:f'SHLR16 R{nn}',0x2A:f'LDS R{nn},PR',
            0x2B:f'JMP  @R{nn}',0x2E:f'LDC R{nn},VBR',
            0x13:f'STC.L GBR,@-R{nn}',
        }
        return t4.get(oc, f'4{nn:X}{oc:02X}'), pc+2
    if hi==0x0:
        if w==0x0009: return 'NOP', pc+2
        if w==0x000B: return 'RTS', pc+2
        if w==0x002B: return 'RTE', pc+2
        if w==0x0008: return 'CLRT', pc+2
        if w==0x0018: return 'SETT', pc+2
        if w==0x0019: return 'DIV0U', pc+2
        if w==0x0028: return 'CLRMAC', pc+2
        if w==0x001B: return 'SLEEP', pc+2
        op=(mm<<4)|d
        t0={0x02:f'STC SR,R{nn}',0x03:f'BSRF R{mm}',0x0A:f'STS MACH,R{nn}',
            0x12:f'STC GBR,R{nn}',0x1A:f'STS MACL,R{nn}',0x22:f'STC VBR,R{nn}',
            0x29:f'MOVT R{nn}',0x2A:f'STS PR,R{nn}',0x3B:f'BRAF R{mm}',
            0x04:f'MOV.B R{mm},@(R0,R{nn})',0x05:f'MOV.W R{mm},@(R0,R{nn})',
            0x06:f'MOV.L R{mm},@(R0,R{nn})',0x07:f'MUL.L R{mm},R{nn}',
            0x0C:f'MOV.B @(R0,R{mm}),R{nn}',0x0D:f'MOV.W @(R0,R{mm}),R{nn}',
            0x0E:f'MOV.L @(R0,R{mm}),R{nn}',0x0F:f'MAC.L @R{mm}+,@R{nn}+'}
        return t0.get(op, f'0x{w:04X}'), pc+2
    if (w>>8)==0xC7: t=(pc&~3)+4+imm8*4; return f'MOVA @(PC+{imm8*4}),R0 ;0x{t:08X}', pc+2
    for code,mnem in [(0xC8,'TST #'),(0xCA,'XOR #'),(0xCB,'OR  #'),(0xC9,'AND #')]:
        if (w>>8)==code: return f'{mnem}0x{imm8:02X},R0', pc+2
    if (w>>8)==0x88:
        imm=imm8; imm=imm|0xFFFFFF00 if imm&0x80 else imm
        return f'CMP/EQ #{imm&0xFF},R0 (0x{imm&0xFF:02X})', pc+2
    if (w>>8)==0x80: return f'MOV.B R0,@(0x{w&0xF:X},R{(w>>4)&0xF})', pc+2
    if (w>>8)==0x81: return f'MOV.W R0,@(0x{(w&0xF)*2:X},R{(w>>4)&0xF})', pc+2
    if (w>>8)==0x84: return f'MOV.B @(0x{w&0xF:X},R{(w>>4)&0xF}),R0', pc+2
    if (w>>8)==0x85: return f'MOV.W @(0x{(w&0xF)*2:X},R{(w>>4)&0xF}),R0', pc+2
    if (w>>8)==0xC4: return f'MOV.B @(0x{imm8:02X},GBR),R0', pc+2
    if (w>>8)==0xC5: return f'MOV.W @(0x{imm8*2:02X},GBR),R0', pc+2
    if (w>>8)==0xC6: return f'MOV.L @(0x{imm8*4:02X},GBR),R0', pc+2
    if (w>>8)==0xC0: return f'MOV.B R0,@(0x{imm8:02X},GBR)', pc+2
    if (w>>8)==0xC1: return f'MOV.W R0,@(0x{imm8*2:02X},GBR)', pc+2
    if (w>>8)==0xC2: return f'MOV.L R0,@(0x{imm8*4:02X},GBR)', pc+2
    if (w>>8)==0xCC: return f'TST.B #0x{imm8:02X},@(R0,GBR)', pc+2
    if (w>>8)==0xCD: return f'AND.B #0x{imm8:02X},@(R0,GBR)', pc+2
    if (w>>8)==0xCE: return f'XOR.B #0x{imm8:02X},@(R0,GBR)', pc+2
    if (w>>8)==0xCF: return f'OR.B #0x{imm8:02X},@(R0,GBR)', pc+2
    if (w>>8)==0xC3: return f'TRAPA #{imm8}', pc+2
    return f'?{w:04X}', pc+2

def disasm(addr, n=120, show_gbr=None):
    """Désassemble avec annotation GBR si fourni"""
    pc = addr
    last_rts = False
    for i in range(n):
        ins, next_pc = sh2_one(pc)
        # Annoter les accès GBR
        if show_gbr and 'GBR' in ins and ('MOV.B' in ins or 'MOV.W' in ins or 'MOV.L' in ins):
            try:
                offset_str = ins.split('(0x')[1].split(',')[0]
                offset = int(offset_str, 16)
                ram_addr = (show_gbr + offset) & 0xFFFFFFFF
                ins += f'  → RAM 0x{ram_addr:08X}'
            except: pass
        print(f'  0x{pc:08X}: {fw_u16(pc):04X}  {ins}')
        if last_rts:
            break
        if any(ins.startswith(x) for x in ['RTS','RTE','JMP ','BRA ']):
            last_rts = True
        pc = next_pc

def title(s): print(f'\n{"="*70}\n  {s}\n{"="*70}')

# ──────────────────────────────────────────────────────────────────────────────
# 1. Suite de sub_27C80 (après 0x27CCA) — counter update et NRC 0x35
# ──────────────────────────────────────────────────────────────────────────────
title("sub_27C80 suite @ 0x27CCC (après BT 0x27CCC)")
disasm(0x27CCC, 100, show_gbr=0xFFFF427B)

# ──────────────────────────────────────────────────────────────────────────────
# 2. Fonction autour de 0x31228 (écrit EEPROM - ref 0x3129C)
# ──────────────────────────────────────────────────────────────────────────────
title("Fonction autour ref sub_6ED78 @ 0x3129C — cherche write EEPROM 0x1FFF")
# Trouver le début de la fonction: remonter depuis 0x31228
disasm(0x31200, 80)

# ──────────────────────────────────────────────────────────────────────────────
# 3. sub_31578 région (ref sub_6ED78 @ 0x31578 — index 0x1FE0 vu dans contexte)
# ──────────────────────────────────────────────────────────────────────────────
title("Fonction autour ref sub_6ED78 @ 0x31578 — index 0x1FE0")
disasm(0x31520, 80)

# ──────────────────────────────────────────────────────────────────────────────
# 4. Chercher SID 0x3D (WriteMemoryByAddress) dans le dispatcher
# ──────────────────────────────────────────────────────────────────────────────
title("Recherche SID 0x3D (WriteMemoryByAddress) dans la flash")
# Chercher les patterns: MOV #0x3D,R0 ou CMP/EQ #0x3D
import struct as s2
for pattern_byte, desc in [(0x3D, '0x3D'), (0x2B, '0x2B TesterPresent'),
                             (0x31, '0x31 ReadMemoryByAddress'),
                             (0x3E, '0x3E TesterPresent')]:
    matches = []
    # CMP/EQ #imm,R0 = 0x88xx
    target = 0x8800 | pattern_byte
    target_bytes = s2.pack('>H', target)
    off = 0
    while True:
        pos = fw.find(target_bytes, off)
        if pos < 0: break
        addr = pos + BASE
        matches.append(addr)
        off = pos + 1
    if matches:
        print(f'\nCMP/EQ #{desc},R0 (0x{target:04X}) trouvé {len(matches)} fois:')
        for a in matches[:6]:
            print(f'  @ 0x{a:08X}')

# ──────────────────────────────────────────────────────────────────────────────
# 5. Analyser sub_27E76 suite (partie SendKey / échec counter update)
# ──────────────────────────────────────────────────────────────────────────────
title("sub_27E76 suite @ 0x27F3C (partie SendKey, counter failure)")
disasm(0x27F3C, 100, show_gbr=0xFFFF427B)

# ──────────────────────────────────────────────────────────────────────────────
# 6. Chercher les write EEPROM avec index 0x1FFF directement
#    Pattern: MOV.W #0x1FFF,R4 avant call sub_6ED78
# ──────────────────────────────────────────────────────────────────────────────
title("Recherche pattern: charge 0x1FFF dans R4 avant write EEPROM")
target_1fff = s2.pack('>H', 0x1FFF)
target_1ff0 = s2.pack('>H', 0x1FF0)

print("\nOccurrences de 0x1FFF dans le firmware (comme mot 16-bit):")
off = 0
while True:
    pos = fw.find(target_1fff, off)
    if pos < 0: break
    addr = pos + BASE
    # Vérifier contexte: est-ce dans une instruction MOV.W ou data?
    # Regarder les 8 bytes autour
    ctx_bytes = fw[max(0,pos-4):pos+8]
    print(f'  @ 0x{addr:08X} (offset 0x{pos:06X}): ctx={ctx_bytes.hex()}')
    off = pos + 1
    if off > 0x200000: break

print("\nOccurrences de 0x1FF0 dans le firmware:")
off = 0
while True:
    pos = fw.find(target_1ff0, off)
    if pos < 0: break
    addr = pos + BASE
    ctx_bytes = fw[max(0,pos-4):pos+8]
    print(f'  @ 0x{addr:08X}: ctx={ctx_bytes.hex()}')
    off = pos + 1
    if off > 0x200000: break
