#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import struct, sys

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

FW_PATH = 'E:/7058/firmware_ewr20.bin'
BASE = 0x400

with open(FW_PATH, 'rb') as f:
    fw = f.read()

def fw_u16(addr):
    off = addr - BASE
    if 0 <= off < len(fw)-1: return struct.unpack_from('>H', fw, off)[0]
    return 0xFFFF

def fw_u32(addr):
    off = addr - BASE
    if 0 <= off < len(fw)-3: return struct.unpack_from('>I', fw, off)[0]
    return 0xFFFFFFFF

def sh2_one(pc):
    w = fw_u16(pc)
    hi=(w>>12)&0xF; nn=(w>>8)&0xF; mm=(w>>4)&0xF; d=w&0xF; imm8=w&0xFF
    if hi==0xA:
        disp=w&0xFFF
        if disp&0x800: disp|=0xFFFFF000
        return f'BRA  0x{(pc+4+disp*2)&0xFFFFFFFF:08X}', pc+2
    if hi==0xB:
        disp=w&0xFFF
        if disp&0x800: disp|=0xFFFFF000
        return f'BSR  0x{(pc+4+disp*2)&0xFFFFFFFF:08X}', pc+2
    for code,mnem in [(0x89,'BT  '),(0x8B,'BF  '),(0x8D,'BT/S'),(0x8F,'BF/S')]:
        if (w>>8)==code:
            disp=imm8
            if disp&0x80: disp|=0xFFFFFF00
            return f'{mnem} 0x{(pc+4+disp*2)&0xFFFFFFFF:08X}', pc+2
    if hi==0xD:
        t=(pc&~3)+4+imm8*4; v=fw_u32(t)
        return f'MOV.L @(PC+{imm8*4}),R{nn} ;[0x{t:08X}]=0x{v:08X}', pc+2
    if hi==0x9:
        t=pc+4+imm8*2; v=fw_u16(t)
        return f'MOV.W @(PC+{imm8*2}),R{nn} ;[0x{t:08X}]=0x{v:04X}', pc+2
    if hi==0xE:
        imm=imm8
        if imm&0x80: imm|=0xFFFFFF00
        return f'MOV  #{imm},R{nn}', pc+2
    if hi==0x7:
        imm=imm8
        if imm&0x80: imm|=0xFFFFFF00
        return f'ADD  #{imm},R{nn}', pc+2
    if hi==0x2:
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
        return f'{ops.get(d, str(d))} R{mm},R{nn}', pc+2
    if hi==0x4:
        oc=(mm<<4)|d
        t4={
            0x00:f'SHLL R{nn}',0x01:f'SHLR R{nn}',0x02:f'STS.L MACH,@-R{nn}',
            0x04:f'ROTL R{nn}',0x05:f'ROTR R{nn}',0x06:f'LDS.L @R{nn}+,MACH',
            0x08:f'SHLL2 R{nn}',0x09:f'SHLR2 R{nn}',0x0A:f'LDS R{nn},MACH',
            0x0B:f'JSR  @R{nn}',0x0E:f'LDC R{nn},SR',
            0x10:f'DT   R{nn}',0x11:f'CMP/PZ R{nn}',0x15:f'CMP/PL R{nn}',
            0x16:f'LDS.L @R{nn}+,MACL',0x17:f'LDC.L @R{nn}+,GBR',
            0x18:f'SHLL8 R{nn}',0x19:f'SHLR8 R{nn}',0x1A:f'LDS R{nn},MACL',
            0x1B:f'TAS.B @R{nn}',0x1E:f'LDC R{nn},GBR',
            0x20:f'SHAL R{nn}',0x21:f'SHAR R{nn}',
            0x22:f'STS.L PR,@-R{nn}',0x23:f'STC.L VBR,@-R{nn}',
            0x24:f'ROTCL R{nn}',0x25:f'ROTCR R{nn}',
            0x26:f'LDS.L @R{nn}+,PR',0x27:f'LDC.L @R{nn}+,VBR',
            0x28:f'SHLL16 R{nn}',0x29:f'SHLR16 R{nn}',
            0x2A:f'LDS R{nn},PR',0x2B:f'JMP  @R{nn}',
            0x2E:f'LDC R{nn},VBR',0x13:f'STC.L GBR,@-R{nn}',
        }
        return t4.get(oc, f'4{nn:X}{oc:02X}'), pc+2
    if hi==0x0:
        if w==0x0009: return 'NOP', pc+2
        if w==0x000B: return 'RTS', pc+2
        if w==0x002B: return 'RTE', pc+2
        op=(mm<<4)|d
        t0={
            0x02:f'STC SR,R{nn}',0x03:f'BSRF R{mm}',
            0x0A:f'STS MACH,R{nn}',0x12:f'STC GBR,R{nn}',
            0x1A:f'STS MACL,R{nn}',0x22:f'STC VBR,R{nn}',
            0x29:f'MOVT R{nn}',0x2A:f'STS PR,R{nn}',0x3B:f'BRAF R{mm}',
            0x04:f'MOV.B R{mm},@(R0,R{nn})',0x05:f'MOV.W R{mm},@(R0,R{nn})',
            0x06:f'MOV.L R{mm},@(R0,R{nn})',0x07:f'MUL.L R{mm},R{nn}',
            0x0C:f'MOV.B @(R0,R{mm}),R{nn}',0x0D:f'MOV.W @(R0,R{mm}),R{nn}',
            0x0E:f'MOV.L @(R0,R{mm}),R{nn}',0x0F:f'MAC.L @R{mm}+,@R{nn}+',
        }
        return t0.get(op, f'0x{w:04X}'), pc+2
    if (w>>8)==0xC7:
        t=(pc&~3)+4+imm8*4
        return f'MOVA @(PC+{imm8*4}),R0 ;0x{t:08X}', pc+2
    for code,mnem in [(0xC8,'TST #'),(0xCA,'XOR #'),(0xCB,'OR  #'),(0xC9,'AND #')]:
        if (w>>8)==code: return f'{mnem}0x{imm8:02X},R0', pc+2
    if (w>>8)==0x88:
        imm=imm8
        if imm&0x80: imm|=0xFFFFFF00
        return f'CMP/EQ #{imm&0xFF},R0', pc+2
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
    if (w>>8)==0xCF: return f'OR.B #0x{imm8:02X},@(R0,GBR)', pc+2
    if (w>>8)==0xC3: return f'TRAPA #{imm8}', pc+2
    return f'?{w:04X}', pc+2

def disasm(addr, n=100, label=''):
    print(f'\n=== {label} @ 0x{addr:08X} ===')
    pc=addr; last_rts=False
    for i in range(n):
        ins, next_pc = sh2_one(pc)
        print(f'  0x{pc:08X}: {fw_u16(pc):04X}  {ins}')
        if last_rts: break
        if any(ins.startswith(x) for x in ['RTS','RTE','JMP ','BRA ']):
            last_rts=True
        pc=next_pc

# 1. fail path sub_27C80: EEPROM[0x1FFF] != 0xAA
disasm(0x27DD8, 50, '0x27DD8 fail path NRC 0x35')

# 2. Debut de la fonction autour 0x3129C (EEPROM write call)
disasm(0x31170, 100, 'sub_31170 complet (cle+EEPROM write)')

# 3. Analyser la section qui appelle sub_6ED78 directement
# Regarder autour de 0x3129C (le pointeur est stocke a cette adresse)
# Chercher la fonction qui contient 0x3129C - regarder instructions juste avant
print('\n=== Octets bruts autour de 0x3129C ===')
for off in range(-20, 20, 2):
    addr = 0x3129C + off
    w = fw_u16(addr)
    ins, _ = sh2_one(addr)
    marker = ' <--- ' if off == 0 else ''
    print(f'  0x{addr:08X}: {w:04X}  {ins}{marker}')

# 4. sub_2851C suite plus loin
disasm(0x285A4, 20, 'sub_2851C: apres BF 0x285A4 (failure branch)')

# 5. Chercher le write EEPROM[0x1FFF] = valeur_echec
# Regarder sub_31170 + sub_311xx pour les appels write
print('\n=== Recherche write EEPROM dans sub_31170 contexte ===')
# Les references write EEPROM etaient: 0x3129C, 0x31578, 0x3179C
# 0x3129C est dans sub_31170 (qui commence a 0x31170)
# Regarder la zone 0x31280-0x312B0
disasm(0x31280, 40, 'Zone 0x31280 (avant ref 6ED78 a 0x3129C)')

# 6. Verifier les valeurs ecrites vers EEPROM 0x1FFF
# sub_31170 lit 0x1FBE et 0x1FBF - ce sont des cles
# Apres verification reussie: que fait il ?
# sub_31170 est appelee depuis sub_27E76 (handler sendkey)
# Chercher ce qui est ecrit en cas d echec dans sub_27E76

print('\n=== sub_27E76 suite (apres 0x27F3C) - partie echec counter ===')
disasm(0x27FA0, 80, 'sub_27E76 tail - counter write on fail')
