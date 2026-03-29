import struct

with open("firmware_ewr20.bin", "rb") as f:
    data = f.read()

BASE = 0x400

def r16(a):
    o = a - BASE
    return struct.unpack_from('>H', data, o)[0] if 0 <= o < len(data)-1 else 0

def r32(a):
    o = a - BASE
    return struct.unpack_from('>I', data, o)[0] if 0 <= o < len(data)-3 else 0

def disasm(start, count, label=''):
    print("\n=== %s @ 0x%08X ===" % (label, start))
    addr = start
    for _ in range(count):
        o = addr - BASE
        if o < 0 or o+2 > len(data): break
        w = r16(addr)
        n = (w>>8)&0xF; m = (w>>4)&0xF; d8 = w&0xFF
        mn = "  0x%08X: %04X  " % (addr, w)
        t = w>>12
        if w in (0x000B, 0x0009): mn += "NOP" if w==0x0009 else "RTS"
        elif t==0xE: v=d8 if d8<128 else d8-256; mn+="MOV #%d,R%d"%(v,n)
        elif t==0x9: ea=addr+4+d8*2; mn+="MOV.W @(PC+%d),R%d ;[0x%08X]=0x%04X"%(d8*2,n,ea,r16(ea))
        elif t==0xD: ea=(addr&~3)+4+d8*4; mn+="MOV.L @(PC+%d),R%d ;[0x%08X]=0x%08X"%(d8*4,n,ea,r32(ea))
        elif t==0x6:
            s={0:'MOV.B @R%m,R%n',1:'MOV.W @R%m,R%n',2:'MOV.L @R%m,R%n',3:'MOV R%m,R%n',
               4:'MOV.B @R%m+,R%n',5:'MOV.W @R%m+,R%n',0xC:'EXTU.B R%m,R%n',0xD:'EXTU.W R%m,R%n'}
            mn+=(s.get(w&0xF,"0x%04X"%w)).replace('%m',str(m)).replace('%n',str(n))
        elif t==0x3:
            s={0:'CMP/EQ R%m,R%n',8:'SUB R%m,R%n',0xC:'ADD R%m,R%n',0xE:'ADDC R%m,R%n'}
            mn+=(s.get(w&0xF,"3x%04X"%w)).replace('%m',str(m)).replace('%n',str(n))
        elif t==0x2:
            s={0:'MOV.B R%m,@R%n',1:'MOV.W R%m,@R%n',2:'MOV.L R%m,@R%n',8:'TST R%m,R%n',0xA:'XOR R%m,R%n'}
            mn+=(s.get(w&0xF,"0x%04X"%w)).replace('%m',str(m)).replace('%n',str(n))
        elif t==0x4:
            s={0x0B:'JSR @R%n',0x2B:'JMP @R%n',0x22:'STS.L PR,@-R%n',0x26:'LDS.L @R%n+,PR',
               0x2A:'LDS R%n,PR',0x1E:'LDC R%n,GBR',0x10:'DT R%n'}
            mn+=(s.get(w&0xFF,"0x%04X"%w)).replace('%n',str(n)).replace('%m',str(m))
        elif t==0x8:
            s8=(w>>8)&0xF; disp=w&0xFF
            if s8==0x8: mn+="CMP/EQ #%d,R0"%disp
            elif s8==0xB: d=disp if disp<128 else disp-256; mn+="BF   0x%08X"%(addr+4+d*2)
            elif s8==0x9: d=disp if disp<128 else disp-256; mn+="BT   0x%08X"%(addr+4+d*2)
            elif s8==0xF: d=disp if disp<128 else disp-256; mn+="BF/S 0x%08X"%(addr+4+d*2)
            elif s8==0xD: d=disp if disp<128 else disp-256; mn+="BT/S 0x%08X"%(addr+4+d*2)
            else: mn+="0x%04X"%w
        elif t==0xA: disp=w&0xFFF; disp=disp|0xFFFFF000 if disp&0x800 else disp; mn+="BRA 0x%08X"%((addr+4+disp*2)&0xFFFFFFFF)
        elif t==0xB: disp=w&0xFFF; disp=disp|0xFFFFF000 if disp&0x800 else disp; mn+="BSR 0x%08X"%((addr+4+disp*2)&0xFFFFFFFF)
        elif t==0x7: v=d8 if d8<128 else d8-256; mn+="ADD #%d,R%d"%(v,n)
        elif t==0x5: mn+="MOV.L @(%d,R%d),R%d"%((w&0xF)*4,m,n)
        elif t==0x1: mn+="MOV.L R%d,@(%d,R%d)"%(n,(w&0xF)*4,m)
        elif t==0xC:
            s=(w>>8)&0xF; disp=w&0xFF
            if s==4: mn+="MOV.B @(%d,GBR),R0"%disp
            elif s==5: mn+="MOV.W @(0x%X,GBR),R0"%(disp*2)
            elif s==8: mn+="TST #0x%02X,R0"%disp
            elif s==9: mn+="AND #0x%02X,R0"%disp
            elif s==0xA: mn+="XOR #0x%02X,R0"%disp
            elif s==0xB: mn+="OR #0x%02X,R0"%disp
            elif s==0: mn+="MOV.B R0,@(%d,GBR)"%disp
            elif s==1: mn+="MOV.W R0,@(%d,GBR)"%(disp*2)
            elif s==7: mn+="MOVA @(%d,PC),R0 ;EA=0x%08X"%(disp*4,(addr&~3)+4+disp*4)
            else: mn+="0x%04X"%w
        elif t==0x0:
            s=w&0xFF
            if s==0x0B: mn+="RTS"
            elif s==0x09: mn+="NOP"
            elif s==0x2B: mn+="RTE"
            elif s==0x2A: mn+="STS PR,R%d"%n
            elif s==0x12: mn+="STC GBR,R%d"%n
            elif (w&0xF)==0x4: mn+="MOV.B @(R0,R%d),R%d"%(m,n)
            elif (w&0xF)==0x5: mn+="MOV.W @(R0,R%d),R%d"%(m,n)
            elif (w&0xF)==0x6: mn+="MOV.L @(R0,R%d),R%d"%(m,n)
            else: mn+="0x%04X"%w
        else: mn+="0x%04X"%w
        print(mn)
        addr += 2
        if mn.strip()=="RTS": break

# ─── Vérifier le call site 0xCAA66 (K-Line ISR) ──────────────────────────
disasm(0xCAA40, 40, "K-Line ISR contexte autour call sub_6F0E8 @ 0xCAA66")

# ─── Le call site 0x28168 (proche de sub_2851C KEY verification) ──────────
disasm(0x28150, 50, "Contexte @ 0x28168 (call sub_6F0E8 proche KEY)")

# ─── sub_6FD8E et 0x6FF0C — sont-ce des checksums ? ────────────────────────
disasm(0x6FD70, 50, "Contexte @ 0x6FD8E (call sub_6F0E8)")

# ─── Résumé checksum : chercher ADD Rm,Rn précédant un CMP/EQ (pattern somme)
print("\n=== Pattern checksum : ADD Rm,Rn suivi de CMP/EQ dans les 20 instr ===")
found = 0
for off in range(0, len(data)-40, 2):
    w = struct.unpack_from('>H', data, off)[0]
    # ADD Rm,Rn = 0x3xxC
    if (w>>12)==0x3 and (w&0xF)==0xC:
        # chercher CMP/EQ dans les 20 instr suivantes
        for fwd in range(2, 42, 2):
            fw = struct.unpack_from('>H', data, off+fwd)[0]
            # CMP/EQ Rm,Rn = 0x3xx0
            if (fw>>12)==0x3 and (fw&0xF)==0x0:
                # Y a-t-il un call EEPROM read nearby (en amont)?
                for bk in range(2, 200, 2):
                    boff = off - bk
                    if boff < 0: break
                    bw = struct.unpack_from('>H', data, boff)[0]
                    if (bw>>12)==0xD:
                        disp2 = bw&0xFF
                        ea2 = (boff&~3)+4+disp2*4
                        if 0 <= ea2 < len(data)-3:
                            v2 = struct.unpack_from('>I', data, ea2)[0]
                            if v2 in (0x6F0E8, 0x6F61C):
                                addr = off+BASE
                                cmp_addr = off+fwd+BASE
                                print("  ADD @ 0x%08X + CMP/EQ @ 0x%08X + EEPROM read → checksum suspect" % (addr, cmp_addr))
                                found += 1
                                if found > 10: break
                if found > 10: break
        if found > 10: break

if found == 0:
    print("  Aucun pattern checksum EEPROM detecte")

# ─── Vérifier 0x1FFE — souvent un checksum byte ────────────────────────────
disasm(0x27D3E, 25, "Lecture EEPROM[0x1FFE] dans sub_27C80 — role ?")
