#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
key_algo_final.py -- Algorithme KEY KWP2000 SID 0x27 02 -- EWR20 SH7058
=========================================================================
RESULTAT : KEY = SEED ^ 0xFFFFFFFF   (complement bitwise 32-bit)

PREUVE par reverse engineering firmware_ewr20.bin (base 0x400) :

  1. sub_2851C (0x02851C) -- verify_key
       7 paires XOR : (received ^ stored) == 0xFFFF pour chaque paire 16-bit
       GBR = 0xFFFFB52C
       stored[0xFFFFB606] = seed >> 16   (word haut)
       stored[0xFFFFB608] = seed & 0xFFFF (word bas)
       received[0xFFFFA08A] = key >> 16
       received[0xFFFFA08C] = key & 0xFFFF
       => key_hi ^ seed_hi == 0xFFFF  =>  key_hi = ~seed_hi
       => key_lo ^ seed_lo == 0xFFFF  =>  key_lo = ~seed_lo
       => KEY = ~SEED = SEED ^ 0xFFFFFFFF

  2. sub_0C1FC0 (0x0C1FC0) -- init_key_defaults
       Initialise les buffers avec des paires XOR complement :
         received = 0x0078,  stored = 0xFF87
         0x0078 ^ 0xFF87 = 0xFFFF ✓
       Confirme que l'invariant (received ^ stored == 0xFFFF) est maintenu
       depuis l'initialisation.

  3. Validation Sprint 2 (seeds capturees physiquement sur ECU reel) :
       seed=0xAF1B51DE -> key=0x50E4AE21
         stored[B606]=0xAF1B XOR received[A08A]=0x50E4 = 0xFFFF ✓
         stored[B608]=0x51DE XOR received[A08C]=0xAE21 = 0xFFFF ✓
       seed=0x6F9C5E81 -> key=0x9063A17E
         0x6F9C ^ 0x9063 = 0xFFFF ✓ | 0x5E81 ^ 0xA17E = 0xFFFF ✓
       seed=0x81CE7CE8 -> key=0x7E318317
         0x81CE ^ 0x7E31 = 0xFFFF ✓ | 0x7CE8 ^ 0x8317 = 0xFFFF ✓
"""

import struct, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# ============================================================
# ALGORITHME KEY
# ============================================================

def compute_key(seed: int) -> int:
    """
    Calcule la cle KWP2000 SID 0x27 02 pour l'ECU EWR20 SH7058.

    Args:
        seed: entier 32-bit recu dans la reponse 0x67 01 xx xx xx xx

    Returns:
        key: entier 32-bit a envoyer dans la requete 0x27 02 xx xx xx xx
    """
    return (seed ^ 0xFFFFFFFF) & 0xFFFFFFFF


# ============================================================
# VALIDATION & AFFICHAGE
# ============================================================

def validate():
    print("=" * 60)
    print("KEY ALGORITHM -- EWR20 SH7058 KWP2000 SID 0x27 02")
    print("KEY = SEED ^ 0xFFFFFFFF")
    print("=" * 60)

    captures = [
        (0xAF1B51DE, 0x50E4AE21, "Sprint 2 session 3"),
        (0x6F9C5E81, 0x9063A17E, "Sprint 2 session 1"),
        (0x81CE7CE8, 0x7E318317, "Sprint 2 session 2"),
    ]

    print("\n[TEST] Validation avec captures physiques ECU reel")
    print("-" * 60)
    all_ok = True
    for seed, expected_key, label in captures:
        key = compute_key(seed)
        ok = key == expected_key

        # decomposer en mots 16-bit
        seed_hi = (seed >> 16) & 0xFFFF
        seed_lo = seed & 0xFFFF
        key_hi  = (key  >> 16) & 0xFFFF
        key_lo  = key  & 0xFFFF
        xor_hi  = seed_hi ^ key_hi
        xor_lo  = seed_lo ^ key_lo

        print(f"\n  {label}")
        print(f"    seed = 0x{seed:08X}  ->  key = 0x{key:08X}  {'OK' if ok else 'ERREUR'}")
        print(f"    stored[B606]=0x{seed_hi:04X}  received[A08A]=0x{key_hi:04X}  XOR=0x{xor_hi:04X} {'[OK]' if xor_hi==0xFFFF else '[FAIL]'}")
        print(f"    stored[B608]=0x{seed_lo:04X}  received[A08C]=0x{key_lo:04X}  XOR=0x{xor_lo:04X} {'[OK]' if xor_lo==0xFFFF else '[FAIL]'}")

        if not ok or xor_hi != 0xFFFF or xor_lo != 0xFFFF:
            all_ok = False

    print()
    print("=" * 60)
    print(f"  RESULTAT GLOBAL : {'TOUTES LES VALIDATIONS PASSENT' if all_ok else 'ECHEC'}")
    print("=" * 60)

    print("""
UTILISATION :
  from key_algo_final import compute_key

  seed = 0xAF1B51DE   # valeur recue dans trame KWP 0x67 01
  key  = compute_key(seed)
  print(f"Key a envoyer : 0x{key:08X}")
  # -> 0x50E4AE21

TRAME KWP2000 SendKey :
  Seed reponse   : C6 FC 10 67 01 AF 1B 51 DE 33
  Key requete    : C6 10 FC 27 02 50 E4 AE 21 FE
  Reponse ECU OK : C2 FC 10 67 02 xx
""")


# ============================================================
# TRACE ASM sub_2851C (proof-of-work)
# ============================================================

def trace_sub_2851C():
    """
    Relit les mots cles du firmware pour confirmer l'algo.
    """
    FW_PATH = 'E:/7058/firmware_ewr20.bin'
    BASE = 0x400
    try:
        with open(FW_PATH, 'rb') as f:
            fw = f.read()
    except FileNotFoundError:
        print(f"[!] Firmware non trouve : {FW_PATH}")
        return

    def fw_u16(a):
        o = a - BASE
        if 0 <= o < len(fw) - 1:
            return struct.unpack_from('>H', fw, o)[0]
        return 0xFFFF

    def fw_u32(a):
        o = a - BASE
        if 0 <= o < len(fw) - 3:
            return struct.unpack_from('>I', fw, o)[0]
        return 0xFFFFFFFF

    print("\n[TRACE] sub_2851C @ 0x02851C -- premiere instruction")
    print(f"  Opcode 0x02851C : 0x{fw_u16(0x02851C):04X}  (attendu: E0B2 = MOV #-0x4E,R0 / ou STS.L PR,@-R15)")
    print(f"  Opcode 0x02851E : 0x{fw_u16(0x02851E):04X}  (GBR setup)")

    # Verifier la constante GBR = 0xB52C en pool
    # sub_2851C charge GBR ~ offset +8
    # Chercher 0xB52C dans les 32 premiers octets de la fonction
    print("\n[TRACE] Recherche constante GBR = 0xB52C dans pool sub_2851C")
    found = False
    for off in range(0, 64, 2):
        v = fw_u16(0x02851C + off)
        if v == 0xB52C:
            print(f"  Trouve 0xB52C @ 0x{0x02851C+off:06X} (offset +{off}) ✓")
            found = True
    if not found:
        # Chercher dans les 128 octets
        for off in range(0, 128, 2):
            v = fw_u16(0x02851C + off)
            if v == 0xB52C:
                print(f"  Trouve 0xB52C @ 0x{0x02851C+off:06X} (offset +{off}) ✓")
                found = True
    if not found:
        print("  [!] 0xB52C non trouve dans les 128 premiers octets de sub_2851C")
        print("  => Cherche dans zone elargie...")
        for off in range(0, 512, 2):
            v = fw_u16(0x02851C + off)
            if v == 0xB52C:
                print(f"  Trouve 0xB52C @ 0x{0x02851C+off:06X} (offset +{off}) ✓")
                found = True

    # Verifier l'offset GBR+0xDA = instruction CX6D qui encode MOV.W @(0xDA,GBR),Rn
    # Opcode: C16D = MOV.W R0,@(0xDA,GBR) avec nn=1, offset=0x6D*2=0xDA
    # En fait pour MOV.W @(disp,GBR),R0 : opcode = 0xC5xx ou 0xC4xx
    # GBR-relative: C4=MOV.B, C5=MOV.W, C6=MOV.L (lecture), C0=MOV.B, C1=MOV.W, C2=MOV.L (ecriture)
    # MOV.W @(0xDA,GBR),R0 : disp = 0xDA/2 = 0x6D → opcode = C56D
    print("\n[TRACE] Recherche opcode C56D (MOV.W @(0xDA,GBR),R0) dans sub_2851C")
    for off in range(0, 200, 2):
        v = fw_u16(0x02851C + off)
        if v == 0xC56D:
            print(f"  Trouve C56D @ 0x{0x02851C+off:06X} (offset +{off}) -- stored[GBR+0xDA] = stored[0xFFFFB606] ✓")

    # Chercher C56E = MOV.W @(0xDC,GBR),R0
    print("[TRACE] Recherche opcode C56E (MOV.W @(0xDC,GBR),R0) dans sub_2851C")
    for off in range(0, 200, 2):
        v = fw_u16(0x02851C + off)
        if v == 0xC56E:
            print(f"  Trouve C56E @ 0x{0x02851C+off:06X} (offset +{off}) -- stored[GBR+0xDC] = stored[0xFFFFB608] ✓")

    # Verifier CMP/EQ R5,Rn avec R5=0xFFFF (verif XOR == 0xFFFF)
    # Pattern: MOV #-1,R5 = EF FF, puis CMP/EQ R5,Rn = 3n50
    print("\n[TRACE] Recherche MOV #-1,R5 (EFFF) = R5=0xFFFF dans sub_2851C")
    for off in range(0, 200, 2):
        v = fw_u16(0x02851C + off)
        if v == 0xEFFF:
            print(f"  Trouve EFFF @ 0x{0x02851C+off:06X} (offset +{off}) -- R5 = 0xFFFFFFFF ✓")


if __name__ == '__main__':
    validate()
    trace_sub_2851C()
