"""
verify_eeprom_dump.py -- Verifier un dump AT24C64 (8KB) avant/apres flash
Usage : python verify_eeprom_dump.py dump.bin

Controles effectues :
  - Taille du dump (8192 octets attendus)
  - Valeur des adresses critiques
  - Verification qu'aucun checksum ne couvre 0x1FFF
  - Affichage des parametres KEY (0x1FB8-0x1FBF)
"""

import sys

if len(sys.argv) != 2:
    print("Usage: python verify_eeprom_dump.py dump.bin")
    sys.exit(1)

with open(sys.argv[1], 'rb') as f:
    eep = bytearray(f.read())

print("Taille dump : %d octets (attendu 8192 pour AT24C64)" % len(eep))
if len(eep) != 0x2000:
    print("  ERREUR: taille incorrecte !")
    sys.exit(1)
else:
    print("  OK: AT24C64 confirme")

print("\nAdresses critiques verrou :")
critical = {
    0x1FFF: "verrou principal",
    0x1FF0: "etat secondaire",
    0x1FF1: "flag secondaire 1",
    0x1FF2: "flag secondaire 2",
    0x1FFE: "seed anti-rejeu (NE PAS TOUCHER)",
}
for addr, label in sorted(critical.items()):
    val = eep[addr]
    status = ""
    if addr == 0x1FFF:
        if val == 0x55:
            status = " <-- VERROUILLE -- ecrire 0x00 pour debloquer"
        elif val == 0x00:
            status = " <-- OK (reset)"
        elif val == 0xAA:
            status = " <-- seed active (phase intermediaire)"
        else:
            status = " <-- valeur inconnue"
    elif addr == 0x1FFE:
        status = " <-- ne pas modifier"
    print("  [0x%04X] = 0x%02X  %s%s" % (addr, val, label, status))

print("\nParametres KEY (0x1FB8-0x1FBF) -- NE PAS MODIFIER :")
for addr in range(0x1FB8, 0x1FC0):
    print("  [0x%04X] = 0x%02X" % (addr, eep[addr]))

print("\nVerification checksum plage 0x1FF0-0x1FFE :")
bloc = eep[0x1FF0:0x1FFF]
somme = sum(bloc) & 0xFF
complement = (~sum(bloc)) & 0xFF
print("  Somme    [0x1FF0..0x1FFE] = 0x%02X" % somme)
print("  Complement                = 0x%02X" % complement)
print("  [0x1FFF]                  = 0x%02X" % eep[0x1FFF])
if eep[0x1FFF] in (somme, complement, (somme + 1) & 0xFF):
    print("  ATTENTION: 0x1FFF pourrait etre un checksum de la plage !")
else:
    print("  OK: 0x1FFF n'est PAS un checksum de la plage -- modification sans risque")

print("\nDiagnostic final :")
if eep[0x1FFF] == 0x00 and eep[0x1FF0] == 0x00:
    print("  PRET -- ECU devrait accepter le SecurityAccess apres reflash")
elif eep[0x1FFF] == 0x55:
    print("  BLOQUE -- lancer fix_eeprom.py puis reflasher")
else:
    print("  Etat inconnu -- analyser manuellement")
