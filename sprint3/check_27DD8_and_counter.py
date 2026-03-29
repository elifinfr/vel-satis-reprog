#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import struct, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
FW_PATH = 'E:/7058/firmware_ewr20.bin'
BASE = 0x400
with open(FW_PATH,'rb') as f: fw = f.read()

def fw_u16(a):
    o=a-BASE
    if 0<=o<len(fw)-1: return struct.unpack_from('>H',fw,o)[0]
    return 0xFFFF
def fw_u32(a):
    o=a-BASE
    if 0<=o<len(fw)-3: return struct.unpack_from('>I',fw,o)[0]
    return 0xFFFFFFFF

def sh2_one(pc):
    w=fw_u16(pc); hi=(w>>12)&0xF; nn=(w>>8)&0xF; mm=(w>>4)&0xF; d=w&0xF; i8=w&0xFF
    if hi==0xA:
        disp=w&0xFFF
        if disp&0x800: disp|=0xFFFFF000
        return f'BRA  0x{(pc+4+disp*2)&0xFFFFFFFF:08X}',pc+2
    if hi==0xB:
        disp=w&0xFFF
        if disp&0x800: disp|=0xFFFFF000
        return f'BSR  0x{(pc+4+disp*2)&0xFFFFFFFF:08X}',pc+2
    for code,mnem in [(0x89,'BT  '),(0x8B,'BF  '),(0x8D,'BT/S'),(0x8F,'BF/S')]:
        if (w>>8)==code:
            disp=i8
            if disp&0x80: disp|=0xFFFFFF00
            return f'{mnem} 0x{(pc+4+disp*2)&0xFFFFFFFF:08X}',pc+2
    if hi==0xD: t=(pc&~3)+4+i8*4; v=fw_u32(t); return f'MOV.L @(PC+{i8*4}),R{nn} ;[0x{t:08X}]=0x{v:08X}',pc+2
    if hi==0x9: t=pc+4+i8*2; v=fw_u16(t); return f'MOV.W @(PC+{i8*2}),R{nn} ;[0x{t:08X}]=0x{v:04X}',pc+2
    if hi==0xE: imm=i8; imm=imm|0xFFFFFF00 if imm&0x80 else imm; return f'MOV  #{imm},R{nn}',pc+2
    if hi==0x7: imm=i8; imm=imm|0xFFFFFF00 if imm&0x80 else imm; return f'ADD  #{imm},R{nn}',pc+2
    if hi==0x2:
        if d==6: return f'MOV.L R{mm},@-R{nn}',pc+2
        if d==2: return f'MOV.L R{mm},@R{nn}',pc+2
        if d==1: return f'MOV.W R{mm},@R{nn}',pc+2
        if d==0: return f'MOV.B R{mm},@R{nn}',pc+2
        if d==8: return f'TST  R{mm},R{nn}',pc+2
        if d==9: return f'AND  R{mm},R{nn}',pc+2
        if d==0xA: return f'XOR  R{mm},R{nn}',pc+2
        if d==0xB: return f'OR   R{mm},R{nn}',pc+2
    if hi==0x6:
        if d==6: return f'MOV.L @R{mm}+,R{nn}',pc+2
        if d==2: return f'MOV.L @R{mm},R{nn}',pc+2
        if d==1: return f'MOV.W @R{mm},R{nn}',pc+2
        if d==0: return f'MOV.B @R{mm},R{nn}',pc+2
        if d==3: return f'MOV  R{mm},R{nn}',pc+2
        if d==0xC: return f'EXTU.B R{mm},R{nn}',pc+2
        if d==0xD: return f'EXTU.W R{mm},R{nn}',pc+2
        if d==0xE: return f'EXTS.B R{mm},R{nn}',pc+2
        if d==0xF: return f'EXTS.W R{mm},R{nn}',pc+2
    if hi==0x1: return f'MOV.L R{nn},@(0x{d*4:X},R{mm})',pc+2
    if hi==0x5: return f'MOV.L @(0x{d*4:X},R{mm}),R{nn}',pc+2
    if hi==0x3:
        ops={0:'CMP/EQ',2:'CMP/HS',3:'CMP/GE',4:'DIV1',5:'DMULU.L',6:'CMP/HI',7:'CMP/GT',8:'SUB',0xA:'SUBC',0xB:'SUBV',0xC:'ADD ',0xD:'DMULS.L',0xE:'ADDC',0xF:'ADDV'}
        return f'{ops.get(d,str(d))} R{mm},R{nn}',pc+2
    if hi==0x4:
        oc=(mm<<4)|d
        t4={0x00:f'SHLL R{nn}',0x01:f'SHLR R{nn}',0x02:f'STS.L MACH,@-R{nn}',0x04:f'ROTL R{nn}',0x05:f'ROTR R{nn}',0x06:f'LDS.L @R{nn}+,MACH',0x08:f'SHLL2 R{nn}',0x09:f'SHLR2 R{nn}',0x0A:f'LDS R{nn},MACH',0x0B:f'JSR  @R{nn}',0x0E:f'LDC R{nn},SR',0x10:f'DT   R{nn}',0x11:f'CMP/PZ R{nn}',0x15:f'CMP/PL R{nn}',0x16:f'LDS.L @R{nn}+,MACL',0x17:f'LDC.L @R{nn}+,GBR',0x18:f'SHLL8 R{nn}',0x19:f'SHLR8 R{nn}',0x1A:f'LDS R{nn},MACL',0x1B:f'TAS.B @R{nn}',0x1E:f'LDC R{nn},GBR',0x20:f'SHAL R{nn}',0x21:f'SHAR R{nn}',0x22:f'STS.L PR,@-R{nn}',0x23:f'STC.L VBR,@-R{nn}',0x24:f'ROTCL R{nn}',0x25:f'ROTCR R{nn}',0x26:f'LDS.L @R{nn}+,PR',0x27:f'LDC.L @R{nn}+,VBR',0x28:f'SHLL16 R{nn}',0x29:f'SHLR16 R{nn}',0x2A:f'LDS R{nn},PR',0x2B:f'JMP  @R{nn}',0x2E:f'LDC R{nn},VBR',0x13:f'STC.L GBR,@-R{nn}'}
        return t4.get(oc, f'4{nn:X}{oc:02X}'),pc+2
    if hi==0x0:
        if w==0x0009: return 'NOP',pc+2
        if w==0x000B: return 'RTS',pc+2
        if w==0x002B: return 'RTE',pc+2
        if d==4: return f'MOV.B R{mm},@(R0,R{nn})',pc+2
        if d==5: return f'MOV.W R{mm},@(R0,R{nn})',pc+2
        if d==6: return f'MOV.L R{mm},@(R0,R{nn})',pc+2
        if d==7: return f'MUL.L R{mm},R{nn}',pc+2
        if d==0xC: return f'MOV.B @(R0,R{mm}),R{nn}',pc+2
        if d==0xD: return f'MOV.W @(R0,R{mm}),R{nn}',pc+2
        if d==0xE: return f'MOV.L @(R0,R{mm}),R{nn}',pc+2
        if d==0xF: return f'MAC.L @R{mm}+,@R{nn}+',pc+2
        op=(mm<<4)|d
        t0={0x02:f'STC SR,R{nn}',0x03:f'BSRF R{mm}',0x0A:f'STS MACH,R{nn}',0x12:f'STC GBR,R{nn}',0x1A:f'STS MACL,R{nn}',0x22:f'STC VBR,R{nn}',0x29:f'MOVT R{nn}',0x2A:f'STS PR,R{nn}',0x3B:f'BRAF R{mm}'}
        return t0.get(op, f'?{w:04X}'),pc+2
    if (w>>8)==0xC7: t=(pc&~3)+4+i8*4; return f'MOVA @(PC+{i8*4}),R0 ;0x{t:08X}',pc+2
    for code,mnem in [(0xC8,'TST #'),(0xCA,'XOR #'),(0xCB,'OR  #'),(0xC9,'AND #')]:
        if (w>>8)==code: return f'{mnem}0x{i8:02X},R0',pc+2
    if (w>>8)==0x88: imm=i8; imm=imm|0xFFFFFF00 if imm&0x80 else imm; return f'CMP/EQ #{imm&0xFF},R0',pc+2
    if (w>>8)==0x80: return f'MOV.B R0,@(0x{w&0xF:X},R{(w>>4)&0xF})',pc+2
    if (w>>8)==0x81: return f'MOV.W R0,@(0x{(w&0xF)*2:X},R{(w>>4)&0xF})',pc+2
    if (w>>8)==0x84: return f'MOV.B @(0x{w&0xF:X},R{(w>>4)&0xF}),R0',pc+2
    if (w>>8)==0x85: return f'MOV.W @(0x{(w&0xF)*2:X},R{(w>>4)&0xF}),R0',pc+2
    if (w>>8)==0xC4: return f'MOV.B @(0x{i8:02X},GBR),R0',pc+2
    if (w>>8)==0xC5: return f'MOV.W @(0x{i8*2:02X},GBR),R0',pc+2
    if (w>>8)==0xC6: return f'MOV.L @(0x{i8*4:02X},GBR),R0',pc+2
    if (w>>8)==0xC0: return f'MOV.B R0,@(0x{i8:02X},GBR)',pc+2
    if (w>>8)==0xC1: return f'MOV.W R0,@(0x{i8*2:02X},GBR)',pc+2
    if (w>>8)==0xC2: return f'MOV.L R0,@(0x{i8*4:02X},GBR)',pc+2
    if (w>>8)==0xCF: return f'OR.B #0x{i8:02X},@(R0,GBR)',pc+2
    if (w>>8)==0xC3: return f'TRAPA #{i8}',pc+2
    return f'?{w:04X}',pc+2

def disasm(addr, n=80, lbl=''):
    if lbl: print(f'\n=== {lbl} @ 0x{addr:08X} ===')
    pc=addr; last_rts=False
    for i in range(n):
        ins,next_pc=sh2_one(pc)
        print(f'  0x{pc:08X}: {fw_u16(pc):04X}  {ins}')
        if last_rts: break
        if any(ins.startswith(x) for x in ['RTS','RTE','JMP ','BRA ']): last_rts=True
        pc=next_pc

# 1. The 0x27DD8 path - original "fail if not 0xAA" from sub_27C80
disasm(0x27DD8, 80, 'sub_27C80 0x27DD8 (EEPROM[0x1FFF] != 0xAA path)')

# 2. What does sub_2E20C do? (called from the fail path 0x284DE)
disasm(0x2E20C, 60, 'sub_2E20C (called from fail path 0x284DE)')

# 3. What is sub_27C0A? (called at 0x27D68 in key verify path)
disasm(0x27C0A, 60, 'sub_27C0A (called before key verify)')

# 4. Check sub_27E12 (called in fail path at 0x27D98)
disasm(0x27E12, 60, 'sub_27E12 (called in fail path)')

# 5. Check 0xC46C8 (the lock write site in C46D6)
disasm(0xC46C8, 30, 'zone 0xC46C8 (just before EEPROM lock write at 0xC46D6)')

# 6. Check 0xC1EB8 (the lock write site in C1EF6)
disasm(0xC1EB8, 40, 'zone 0xC1EB8 (before EEPROM lock write at 0xC1EF6)')

# 7. The failure counter tracking: look for EEPROM address 0x1FF1 or 0x1FFD or similar
# that might track count of attempts
print()
print('=== EEPROM reads for attempt counter addresses (0x1FF1-0x1FFD) ===')
counter_addrs = list(range(0x1FF1, 0x1FFE)) + [0x1FFC, 0x1FFD]
for a in range(0x27000, 0x30000, 2):
    w = fw_u16(a)
    if (w>>12)==0x9:
        i8 = w&0xFF; rn = (w>>8)&0xF
        t = a+4+i8*2
        val = fw_u16(t)
        if val in counter_addrs:
            print(f'  0x{a:08X}: MOV.W @PC,R{rn} = 0x{val:04X}  (potential counter addr)')
