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
        if d==5: return f'MOV.W R{mm},@-R{nn}',pc+2
        if d==4: return f'MOV.B R{mm},@-R{nn}',pc+2
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
        t0={0x02:f'STC SR,R{nn}',0x03:f'BSRF R{mm}',0x0A:f'STS MACH,R{nn}',0x12:f'STC GBR,R{nn}',0x1A:f'STS MACL,R{nn}',0x22:f'STC VBR,R{nn}',0x29:f'MOVT R{nn}',0x2A:f'STS PR,R{nn}',0x3B:f'BRAF R{mm}',0x23:f'STC.L VBR,@-R{nn}'}
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

# 1. The function containing the LOCK write at 0x34CF8
# Find function start by going back to find STS.L PR,@-R15
print('=== Finding function start before 0x34CF4 ===')
for addr in range(0x34CF4, 0x34000, -2):
    w = fw_u16(addr)
    if w == 0x4F22:  # STS.L PR,@-R15
        print(f'  Possible func start: 0x{addr:08X}')
        if addr < 0x34CF4 - 200:
            break
        break

disasm(0x34C00, 100, 'Function containing LOCK write (0x34CF8)')

# 2. Find callers of this function (in range 0x27000-0x35000)
# First find function entry point
# Look for function that contains 0x34CF8 by finding cross-refs
print()
print('=== Cross-refs to range 0x34C00-0x34D40 ===')
for a in range(0x20000, 0x34C00, 2):
    w = fw_u16(a)
    if (w>>12)==0xB:  # BSR
        disp=w&0xFFF
        if disp&0x800: disp|=0xFFFFF000
        t=(a+4+disp*2)&0xFFFFFFFF
        if 0x34C00 <= t <= 0x34D40:
            print(f'  BSR @ 0x{a:08X} -> 0x{t:08X}')
    elif (w>>12)==0xD:
        nn=(w>>8)&0xF; i8=w&0xFF
        t=(a&~3)+4+i8*4
        v=fw_u32(t)
        if 0x34C00 <= v <= 0x34D40:
            # check next few for JSR @Rn
            for c in [a+2,a+4,a+6]:
                cw=fw_u16(c)
                if cw==(0x4000|(nn<<8)|0x0B):
                    print(f'  JSR @ 0x{c:08X} -> 0x{v:08X}')

# 3. Scan for write 0xAA to EEPROM[0x1FFF] (the seed-active marker)
# sub_6EBD8 or sub_6ED78 call with R4=0x1FFF and R5=0xAA
print()
print('=== Search: write 0xAA to EEPROM[0x1FFF] ===')
for a in range(0x27000, 0x36000, 2):
    w = fw_u16(a)
    if (w>>12)==0x9 and ((w>>8)&0xF)==4:  # MOV.W @PC,R4
        i8=w&0xFF; t=a+4+i8*2
        if fw_u16(t)==0x1FFF:
            # Look for R5=0xAA nearby and JSR
            for check in range(a-10, a+16, 2):
                cw = fw_u16(check)
                if (cw>>8)==0xE5 and (cw&0xFF)==0xAA:  # MOV #0xAA,R5
                    print(f'  @ 0x{a:08X}: R4=0x1FFF, MOV#0xAA,R5 @ 0x{check:08X}')
                # Check for delay slot MOV #0xAA,R5 after JSR
                if (cw>>8)==0xE5:  # MOV #imm,R5
                    imm = cw&0xFF
                    if imm&0x80: imm|=0xFFFFFF00
                    if imm==0xAA or imm==-86:
                        # Check if prev instruction is JSR
                        cw2 = fw_u16(check-2)
                        if (cw2&0xF00F)==0x400B:  # JSR @Rn
                            print(f'  @ 0x{a:08X}: R4=0x1FFF, delay-slot R5=0xAA after JSR @ 0x{check-2:08X}')

# 4. Also scan broader: any EEPROM write (sub_6ED78 or sub_6EBD8) with 0x1FFF as R4
print()
print('=== All EEPROM writes with R4=0x1FFF (scan 0x20000-0x40000) ===')
T6EBD8 = 0x0006EBD8
T6ED78 = 0x0006ED78
for a in range(0x20000, 0x40000, 2):
    w = fw_u16(a)
    if (w>>12)==0xD:  # MOV.L @PC, Rn
        nn=(w>>8)&0xF; i8=w&0xFF
        t=(a&~3)+4+i8*4
        v=fw_u32(t)
        if v in (T6EBD8, T6ED78):
            fname = 'sub_6EBD8' if v==T6EBD8 else 'sub_6ED78'
            # Find JSR
            for c in [a+2,a+4,a+6]:
                cw=fw_u16(c)
                if cw==(0x4000|(nn<<8)|0x0B):
                    # look back for R4=0x1FFF
                    for back in range(a-30, a+2, 2):
                        bw=fw_u16(back)
                        if (bw>>12)==0x9 and ((bw>>8)&0xF)==4:
                            bi8=bw&0xFF; bt=back+4+bi8*2
                            if fw_u16(bt)==0x1FFF:
                                # Get R5 from delay slot
                                ds_w = fw_u16(c+2)
                                ds_r5 = None
                                if (ds_w>>8)==0xE5:
                                    ds_r5 = ds_w&0xFF
                                    if ds_r5&0x80: ds_r5|=0xFFFFFF00
                                print(f'  {fname} called @ 0x{c:08X} with R4=0x1FFF (loaded@0x{back:08X}), delay_slot_R5={hex(ds_r5) if ds_r5 is not None else "?"}')
                        break

# 5. What happens at 0x28008 (where sub_27E76 jumps to)?
disasm(0x28008, 100, 'sub_27E76 tail @ 0x28008')
