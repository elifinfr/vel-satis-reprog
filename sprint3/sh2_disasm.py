#!/usr/bin/env python3
"""
Désassembleur SH-2 minimal pour analyse firmware EWR20
Ciblé sur les fonctions EEPROM et SID27 counter
"""
import struct
import sys

FW_PATH = "E:/7058/firmware_ewr20.bin"
BASE = 0x400  # adresse de début dans l'espace MCU

with open(FW_PATH, 'rb') as f:
    fw = f.read()

print(f"Firmware: {len(fw)} bytes (0x{len(fw):X}), base MCU=0x{BASE:08X}")

def fw_read_u16(addr):
    off = addr - BASE
    if 0 <= off < len(fw)-1:
        return struct.unpack_from('>H', fw, off)[0]
    return 0xFFFF

def fw_read_u32(addr):
    off = addr - BASE
    if 0 <= off < len(fw)-3:
        return struct.unpack_from('>I', fw, off)[0]
    return 0xFFFFFFFF

def fw_read_bytes(addr, n):
    off = addr - BASE
    if 0 <= off < len(fw)-n:
        return fw[off:off+n]
    return bytes(n)

def sh2_disasm_one(pc):
    """Désassemble une instruction SH-2 @ pc, retourne (str, next_pc)"""
    w = fw_read_u16(pc)
    hi = (w >> 12) & 0xF
    nn = (w >> 8) & 0xF
    mm = (w >> 4) & 0xF
    d  =  w & 0xF
    imm8 = w & 0xFF
    imm4 = w & 0xF
    ins = f'???? 0x{w:04X}'

    if w == 0x000B: ins = 'RTS'
    elif w == 0x0009: ins = 'NOP'
    elif w == 0x002B: ins = 'RTE'
    elif w == 0x0028: ins = 'CLRMAC'
    elif w == 0x0008: ins = 'CLRT'
    elif w == 0x0018: ins = 'SETT'
    elif w == 0x0019: ins = 'DIV0U'
    elif w == 0x001B: ins = 'SLEEP'
    elif hi == 0xA:  # BRA
        disp = w & 0xFFF
        if disp & 0x800: disp |= 0xFFFFF000
        target = pc + 4 + disp*2
        ins = f'BRA  0x{target:08X}'
    elif hi == 0xB:  # BSR
        disp = w & 0xFFF
        if disp & 0x800: disp |= 0xFFFFF000
        target = pc + 4 + disp*2
        ins = f'BSR  0x{target:08X}'
    elif (w & 0xFF00) == 0x8900:  # BT
        disp = imm8
        if disp & 0x80: disp |= 0xFFFFFF00
        target = pc + 4 + disp*2
        ins = f'BT   0x{target:08X}'
    elif (w & 0xFF00) == 0x8B00:  # BF
        disp = imm8
        if disp & 0x80: disp |= 0xFFFFFF00
        target = pc + 4 + disp*2
        ins = f'BF   0x{target:08X}'
    elif (w & 0xFF00) == 0x8D00:  # BT/S
        disp = imm8
        if disp & 0x80: disp |= 0xFFFFFF00
        target = pc + 4 + disp*2
        ins = f'BT/S 0x{target:08X}'
    elif (w & 0xFF00) == 0x8F00:  # BF/S
        disp = imm8
        if disp & 0x80: disp |= 0xFFFFFF00
        target = pc + 4 + disp*2
        ins = f'BF/S 0x{target:08X}'
    elif hi == 0xD:  # MOV.L @(disp,PC),Rn
        disp = imm8
        target = (pc & ~3) + 4 + disp*4
        val = fw_read_u32(target)
        ins = f'MOV.L @(d:{disp}),R{nn}  ; [0x{target:08X}]=0x{val:08X}'
    elif hi == 0x9:  # MOV.W @(disp,PC),Rn
        disp = imm8
        target = pc + 4 + disp*2
        val = fw_read_u16(target)
        ins = f'MOV.W @(d:{disp}),R{nn}  ; [0x{target:08X}]=0x{val:04X}'
    elif hi == 0xE:  # MOV #imm,Rn
        imm = imm8
        if imm & 0x80: imm |= 0xFFFFFF00
        ins = f'MOV  #0x{imm&0xFFFFFFFF:X},R{nn}'
    elif hi == 0x6:
        ops = {0:'MOV.B', 1:'MOV.W', 2:'MOV.L', 3:'MOV',
               4:'MOV.B', 5:'MOV.W', 6:'MOV.L', 7:'NOT',
               8:'SWAP.B', 9:'SWAP.W', 0xA:'NEGC', 0xB:'NEG',
               0xC:'EXTU.B', 0xD:'EXTU.W', 0xE:'EXTS.B', 0xF:'EXTS.W'}
        op = ops.get(d, f'6{d:X}')
        if d <= 2: ins = f'{op} @R{mm},R{nn}'
        else: ins = f'{op} R{mm},R{nn}'
    elif hi == 0x2:
        ops = {0:'MOV.B', 1:'MOV.W', 2:'MOV.L',
               4:'MOV.B', 5:'MOV.W', 6:'MOV.L',
               7:'DIV0S', 8:'TST', 9:'AND', 0xA:'XOR', 0xB:'OR',
               0xC:'MUL.L', 0xD:'???', 0xE:'MULS.W', 0xF:'MULU.W'}
        op = ops.get(d, f'2{d:X}')
        if d in [0,1,2]: ins = f'{op} R{nn},@R{mm}'
        elif d in [4,5,6]: ins = f'{op} R{nn},@-R{mm}'
        else: ins = f'{op} R{mm},R{nn}'
    elif hi == 0x1:  # MOV.L Rn,@(disp,Rm)
        disp = d * 4
        ins = f'MOV.L R{nn},@(0x{disp:X},R{mm})'
    elif hi == 0x5:  # MOV.L @(disp,Rm),Rn
        disp = d * 4
        ins = f'MOV.L @(0x{disp:X},R{mm}),R{nn}'
    elif hi == 0x4:
        op_code = (mm << 4) | d
        ops4 = {
            0x00:'SHLL',0x01:'SHLR',0x02:'STS.L MACH,@-Rn',
            0x04:'ROTL',0x05:'ROTR',0x06:'LDS.L @Rn+,MACH',
            0x08:'SHLL2',0x09:'SHLR2',0x0A:'LDS Rn,MACH',0x0B:'JSR @Rn',
            0x0E:'LDC Rn,SR',0x0F:'MAC.W @Rm+,@Rn+',
            0x10:'DT',0x11:'CMP/PZ',0x14:'SETRC',0x15:'CMP/PL',
            0x16:'LDS.L @Rn+,MACL',0x17:'LDCL @Rn+,GBR',
            0x18:'SHLL8',0x19:'SHLR8',0x1A:'LDS Rn,MACL',0x1B:'TAS.B @Rn',
            0x1E:'LDC Rn,GBR',
            0x20:'SHAL',0x21:'SHAR',0x22:'STS.L PR,@-Rn',0x23:'STC.L VBR,@-Rn',
            0x24:'ROTCL',0x25:'ROTCR',0x26:'LDS.L @Rn+,PR',0x27:'LDC.L @Rn+,VBR',
            0x28:'SHLL16',0x29:'SHLR16',0x2A:'LDS Rn,PR',0x2B:'JMP @Rn',
            0x2E:'LDC Rn,VBR',
        }
        ins = ops4.get(op_code, f'4{nn:X}{op_code:02X}')
        ins = ins.replace('Rn', f'R{nn}').replace('Rm', f'R{mm}')
    elif hi == 0x3:
        ops3 = {0:'CMP/EQ',2:'CMP/HS',3:'CMP/GE',4:'DIV1',5:'DMULU.L',
                6:'CMP/HI',7:'CMP/GT',8:'SUB',0xA:'SUBC',0xB:'SUBV',
                0xC:'ADD',0xD:'DMULS.L',0xE:'ADDC',0xF:'ADDV'}
        op = ops3.get(d, f'3{d:X}')
        ins = f'{op} R{mm},R{nn}'
    elif hi == 0x7:  # ADD #imm,Rn
        imm = imm8
        if imm & 0x80: imm |= 0xFFFFFF00
        ins = f'ADD  #0x{imm&0xFF:02X},R{nn}'
    elif (w & 0xFF00) == 0xC700:  # MOVA
        disp = imm8
        target = (pc & ~3) + 4 + disp*4
        ins = f'MOVA @(d:{disp}),R0  ; 0x{target:08X}'
    elif (w & 0xFF00) == 0xC800:
        ins = f'TST  #0x{imm8:02X},R0'
    elif (w & 0xFF00) == 0xCA00:
        ins = f'XOR  #0x{imm8:02X},R0'
    elif (w & 0xFF00) == 0xCB00:
        ins = f'OR   #0x{imm8:02X},R0'
    elif (w & 0xFF00) == 0xC900:
        ins = f'AND  #0x{imm8:02X},R0'
    elif (w & 0xFF00) == 0x8800:  # CMP/EQ #imm,R0
        imm = imm8
        if imm & 0x80: imm |= 0xFFFFFF00
        ins = f'CMP/EQ #{imm},R0'
    elif (w & 0xFF00) == 0x8000:
        ins = f'MOV.B R0,@(0x{imm4:X},R{mm})'
    elif (w & 0xFF00) == 0x8100:
        ins = f'MOV.W R0,@(0x{imm4*2:X},R{mm})'
    elif (w & 0xFF00) == 0x8400:
        ins = f'MOV.B @(0x{imm4:X},R{mm}),R0'
    elif (w & 0xFF00) == 0x8500:
        ins = f'MOV.W @(0x{imm4*2:X},R{mm}),R0'
    elif hi == 0x0:
        op = (mm << 4) | d
        ops0 = {
            0x02:f'STC SR,R{nn}',0x03:f'BSRF R{mm}',
            0x08:'CLRT',0x09:'NOP',0x0A:f'STS MACH,R{nn}',0x0B:'RTS',
            0x12:f'STC GBR,R{nn}',0x18:'SETT',0x19:'DIV0U',
            0x1A:f'STS MACL,R{nn}',0x1B:'SLEEP',
            0x22:f'STC VBR,R{nn}',0x28:'CLRMAC',
            0x29:f'MOVT R{nn}',0x2A:f'STS PR,R{nn}',0x2B:'RTE',
            0x3B:f'BRAF R{mm}',
            0x04:f'MOV.B R{mm},@(R0,R{nn})',0x05:f'MOV.W R{mm},@(R0,R{nn})',
            0x06:f'MOV.L R{mm},@(R0,R{nn})',0x07:f'MUL.L R{mm},R{nn}',
            0x0C:f'MOV.B @(R0,R{mm}),R{nn}',0x0D:f'MOV.W @(R0,R{mm}),R{nn}',
            0x0E:f'MOV.L @(R0,R{mm}),R{nn}',
            0x0F:f'MAC.L @R{mm}+,@R{nn}+',
        }
        ins = ops0.get(op, f'0{nn:X}{op:02X}')

    return ins, pc + 2

def disasm_func(addr, max_insn=120, stop_at_rts=True):
    """Désassemble une fonction complète"""
    pc = addr
    last_was_jump = False
    delay_slot = False
    count = 0
    results = []

    while count < max_insn:
        ins, next_pc = sh2_disasm_one(pc)
        results.append((pc, fw_read_u16(pc), ins))

        if delay_slot:
            break  # Arrêt après delay slot

        # Détecter fin de fonction
        is_jump = any(ins.startswith(x) for x in
                      ['RTS', 'RTE', 'JMP', 'BRA ', 'SLEEP'])
        if is_jump and stop_at_rts:
            delay_slot = True  # Prochain = delay slot, puis stop

        pc = next_pc
        count += 1

    return results

def print_func(addr, name="", max_insn=120):
    print(f"\n{'='*72}")
    print(f"  {name or f'sub_{addr:X}'}  @ 0x{addr:08X}")
    print(f"{'='*72}")
    results = disasm_func(addr, max_insn)
    for pc, raw, ins in results:
        print(f"  0x{pc:08X}: {raw:04X}  {ins}")
    return results

# ── Analyser les fonctions critiques ───────────────────────────────────────────

targets = [
    (0x27C80, "sub_27C80 — SID27 dispatcher + counter", 100),
    (0x27E76, "sub_27E76 — handler RequestSeed+SendKey", 100),
    (0x283EC, "sub_283EC — orchestrateur seed+counter FLASH", 100),
    (0x6ED78, "sub_6ED78 — driver SCI2 EEPROM write CRITIQUE", 80),
    (0x6F0E8, "sub_6F0E8 — driver SCI2 EEPROM read", 60),
    (0x6F61C, "sub_6F61C — getter EEPROM avec retry", 60),
    (0x31170, "sub_31170 — construction KEY (bit perm+EEPROM)", 80),
]

for addr, name, max_i in targets:
    print_func(addr, name, max_i)
    print()
