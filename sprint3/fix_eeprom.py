"""
fix_eeprom.py -- Modifier les adresses critiques dans un dump AT24C64 (8KB)
Usage : python fix_eeprom.py dump_original.bin dump_fixed.bin

Adresses a mettre a 0x00 :
  0x1FFF  verrou principal NRC 0x35 (0x55 = bloque, 0x00 = autorise)
  0x1FF0  etat secondaire
  0x1FF1  flag secondaire 1
  0x1FF2  flag secondaire 2

Adresses a NE PAS TOUCHER :
  0x1FFE  seed anti-rejeu (compare a seed precedente dans sub_27C80)
  0x1FB8-0x1FBF  parametres KEY (constants algo verification)
"""

import sys

if len(sys.argv) != 3:
    print("Usage: python fix_eeprom.py dump_original.bin dump_fixed.bin")
    sys.exit(1)

src = sys.argv[1]
dst = sys.argv[2]

with open(src, 'rb') as f:
    data = bytearray(f.read())

if len(data) != 0x2000:
    print("AVERTISSEMENT: taille inattendue = %d octets (attendu 8192 pour AT24C64)" % len(data))

print("Avant modification :")
for addr, label in [(0x1FFF, "verrou principal"), (0x1FF0, "etat secondaire"),
                    (0x1FF1, "flag secondaire 1"), (0x1FF2, "flag secondaire 2"),
                    (0x1FFE, "seed anti-rejeu (NON MODIFIE)"),
                    (0x1FB8, "KEY param 0"), (0x1FB9, "KEY param 1"),
                    (0x1FBA, "KEY param 2"), (0x1FBB, "KEY param 3")]:
    print("  EEPROM[0x%04X] = 0x%02X  (%s)" % (addr, data[addr], label))

data[0x1FFF] = 0x00
data[0x1FF0] = 0x00
data[0x1FF1] = 0x00
data[0x1FF2] = 0x00

print("\nApres modification :")
for addr in [0x1FFF, 0x1FF0, 0x1FF1, 0x1FF2]:
    print("  EEPROM[0x%04X] = 0x%02X" % (addr, data[addr]))

with open(dst, 'wb') as f:
    f.write(data)

print("\nFichier cree : %s" % dst)
print("Flasher ce fichier avec AsProgrammer (AT24C64, adresse I2C 0x50)")
print("IMPORTANT: verifier les adresses 0x1FFE/0x1FB8-0x1FBB non modifiees")
