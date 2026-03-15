# test_keys_ewr20.py
# Teste nos candidats key sur le seed reçu

def candidate_1(seed):
    # Stride=3, XOR simple
    return (seed ^ 0x5024) & 0xFFFF

def candidate_2(seed):
    # Byte swap + XOR
    swapped = ((seed & 0xFF) << 8) | ((seed >> 8) & 0xFF)
    return swapped ^ 0x2400

def candidate_3(seed):
    # Rotation + constantes stride=1
    # key_const = {0x0A, 0x21, 0xEA, 0x64}
    k = (0x0A << 8) | 0x21
    return (seed ^ k) & 0xFFFF

def candidate_4(seed):
    # Complement
    return (~seed) & 0xFFFF

def candidate_5(seed):
    # Subaru-style sur 16bit
    key = seed
    for _ in range(16):
        if key & 0x8000:
            key = ((key << 1) ^ 0x8621) & 0xFFFF
        else:
            key = (key << 1) & 0xFFFF
    return key

def candidate_6(seed):
    # Pattern Denso 16bit LFSR avec constante 0x86E7
    key = seed
    for _ in range(16):
        if key & 0x8000:
            key = ((key << 1) ^ 0x86E7) & 0xFFFF
        else:
            key = (key << 1) & 0xFFFF
    return key

def candidate_7(seed):
    # Autre constante 0x8AA7
    key = seed
    for _ in range(16):
        if key & 0x8000:
            key = ((key << 1) ^ 0x8AA7) & 0xFFFF
        else:
            key = (key << 1) & 0xFFFF
    return key

# Remplace par le seed reçu de l'ECU
seed = 0x0000  # ← METTRE LE VRAI SEED ICI

print("Seed: 0x%04X" % seed)
print("")
print("Candidats key:")
print("  1: 0x%04X  (XOR 0x5024)" % candidate_1(seed))
print("  2: 0x%04X  (swap+XOR)" % candidate_2(seed))
print("  3: 0x%04X  (XOR stride=1)" % candidate_3(seed))
print("  4: 0x%04X  (complement)" % candidate_4(seed))
print("  5: 0x%04X  (LFSR 0x8621)" % candidate_5(seed))
print("  6: 0x%04X  (LFSR 0x86E7)" % candidate_6(seed))
print("  7: 0x%04X  (LFSR 0x8AA7)" % candidate_7(seed))
print("")
print("Commandes nisprog a tester:")
for i, f in enumerate([candidate_1,candidate_2,candidate_3,
                        candidate_4,candidate_5,candidate_6,candidate_7], 1):
    k = f(seed)
    print("  setkeys %08X  # candidat %d" % (k << 16, i))