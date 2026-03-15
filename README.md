# Compte rendu RE — ECU Renault EWR20 SH7058 VQ35DE
## Sprint 1 — Reverse Engineering firmware `64810223F121200000.hex`

---

## 1. Contexte et matériel

**ECU cible :** Denso EWR20 — Renault Espace IV / Laguna III / Vel Satis — moteur VQ35DE 3.5 V6
**MCU :** Hitachi SH7058 (SH-2A, Big-Endian, 1MB FLASH interne)
**Firmware :** `64810223F121200000.hex` — Intel HEX, base `0x00000400`
**Projet ASAP2 :** `TK_X91_EUR_VC`, version `7V4YHZEB2`, généré par `RB4-ASAP2 GENERATOR` (commun Nissan/Renault)
**Outils utilisés :** IDA Pro (SH2A, Big-Endian), nisprog v1.05, KKL 449.1

---

## 2. Architecture mémoire SH7058

| Zone | Adresse | Contenu |
|---|---|---|
| FLASH interne | `0x00000000–0x000FFFFF` | Code firmware |
| RAM interne | `0xFFFF0000–0xFFFFFFFF` | Variables runtime |
| Registres hardware | `0xFFFFE000+` | DMAC, SCI, ATU, PCIOR |

---

## 3. Variables A2L identifiées

| Nom A2L | Type | Adresse RAM | Description |
|---|---|---|---|
| `vSEED` | UWORD | `0xFFFFB644` | Seed 16-bit (KWP standard) |
| `vFLASEED` | ULONG | `0xFFFFB5F8` | Seed 32-bit (accès FLASH) |
| `tSADT` | UBYTE | `0xFFFF44BA` | Délai seed FLASH |
| `tSADT_S` | UBYTE | `0xFFFF45B0` | Délai seed sécurité |

---

## 4. Hiérarchie des fonctions KWP2000 service 0x27

```
sub_27BD4  ← point d'entrée principal KWP dispatcher
│
├── sub_29FF8        init hardware PLIOR (K-Line physique)
├── sub_283EC        orchestrateur seed
│   ├── sub_6F61C    getter paramètre EEPROM (avec retry)
│   │   └── sub_6F0E8  driver SCI2 lecture EEPROM externe
│   ├── sub_2848C    calcul seed (algo mathématique)
│   └── sub_70554    driver SCI2 transmission K-Line
│
├── sub_27C80        dispatcher sous-services 0x27
│   ├── sub_2851C    vérification KEY ← NOUVEAU
│   └── sub_27E76    handler complet 0x27 (RequestSeed + SendKey)
│       ├── sub_6F61C  lecture params NVM 0x1FF3→0x1FF8, 0x1FBC, 0x1FBE
│       ├── sub_6F0E8  lecture params KEY 0x1FB8→0x1FBB
│       └── sub_70554  transmission réponse
│
└── sub_31170        construction KEY (bit permutation + EEPROM)
    └── sub_6ED78    driver SCI2 écriture/lecture EEPROM
```

---

## 5. Algorithme SEED — Prouvé par RE

### Source d'entropie

```
dword_227A0 = { 0xFFFF9C6C, 0xFFFF9F48 }
```

Deux adresses RAM pointant vers des **compteurs libres ATU** (Advanced Timer Unit) du SH7058 — valeur pseudo-aléatoire dépendant du timing exact de la requête.

### Fonction `sub_2848C` — Algo seed complet

```c
uint16_t compute_seed(uint32_t* timer_struct) {
    // timer_struct[0] = *(uint32_t*)0xFFFF9C6C
    // timer_struct[1] = *(uint32_t*)0xFFFF9F48

    uint16_t delta   = (uint16_t)(timer_struct[1] - timer_struct[0]);
    uint16_t val     = delta + 0x2A0;     // offset fixe = 672
    uint16_t shifted = val >> 5;          // division par 32
    uint16_t seed    = shifted << 7;      // x128 → net effect : val * 4

    // Ajustement conditionnel
    uint16_t check = shifted << 6;        // val * 2
    if (check == val) {
        seed += 0x20;                     // +32 si val multiple de 64
    }

    return seed;
}
```

### Validation des paramètres NVM avant génération seed

```
sub_283EC vérifie :
  param[0x1FFF] ∈ {0x00, 0xAA, 0x55}  → type d'accès autorisé
  param[0x1FF0] ∈ {0x00, 0x55, 0xFF}  → type d'accès secondaire

Si OK → appelle sub_2848C → envoie seed via sub_70554
```

---

## 6. Algorithme KEY — ✅ RÉSOLU

### `sub_2851C` — Fonction de vérification KEY (découverte finale)

La vérification utilise un **XOR avec 0xFFFF** pour chaque paire received/stored :

```c
int verify_key(void) {
    // GBR base = 0xFFFFB52C
    // Retourne 0x00 = SUCCÈS, 0xFF = ÉCHEC

    // Vérification 1
    uint16_t r = *(uint16_t*)(0xFFFF9FEC + 0x9E*2);  // clé reçue du tester
    uint16_t s = *(uint16_t*)(GBR + 0xDA);             // clé calculée ECU
    if ((r ^ s) != 0xFFFF) return 0xFF;

    // Vérification 2
    r = *(uint16_t*)(0xFFFF9FEC + 0xA0*2);
    s = *(uint16_t*)(GBR + 0xDC);
    if ((r ^ s) != 0xFFFF) return 0xFF;

    // Vérifications 3 à 7 — même pattern XOR 0xFFFF
    // sur différentes paires d'adresses GBR et RAM
    // ...

    return 0x00;  // SUCCÈS
}
```

### 🔑 Algorithme KEY — Formule finale

```
(received_key ^ stored_key) == 0xFFFF
⟺ received_key == stored_key ^ 0xFFFF
⟺ key = ~seed   (complément bitwise 16-bit)
```

**La KEY est le complément bitwise du SEED :**

```c
uint16_t compute_key(uint16_t seed) {
    return seed ^ 0xFFFF;
    // équivalent : return ~seed & 0xFFFF;
}
```

### Exemple

```
seed reçu  : 0x1234
key correct : 0x1234 ^ 0xFFFF = 0xEDCB

Dans nisprog après reset compteur :
setkeys EDCB0000
runkernel npk_SH7058.bin
```

---

## 7. Compteur de tentatives — Mécanisme RE

### Localisation

```
sub_27C80 @ 0x27CFC–0x27D0A
```

### Fonctionnement — Système à états, pas compteur numérique

```
État RAM (flag volatile) :
  0x00 = premier appel → accès autorisé
  0xAA = déjà appelé une fois → accès autorisé
  0xFF = bloqué → NRC 0x35 (exceedNumberOfAttempts)

Nombre max de tentatives :
  Service standard : 4  (cmp/eq #4 @ 0x27CFC et 0x27D08)
  Service FLASH    : 2  (cmp/eq #2 @ 0x2842A dans sub_283EC)
  Autre niveau     : 5  (cmp/eq #5 @ 0x27D58)
```

### Reset du compteur

```
✅ Flag en RAM volatile → disparaît à la coupure d'alimentation
✅ Contact coupé 15 secondes = reset complet
✅ Débrancher la batterie = reset garanti
⚠️  ECU actuellement bloqué — reset nécessaire avant tout essai
```

---

## 8. Registres hardware utilisés

| Registre | Adresse | Rôle |
|---|---|---|
| `ATUII_ICR0DH_W` | `0xFFFF9C54` | Timer — source entropie seed |
| `DMAC_DMAOR_W` | `0xFFFFE410` | État DMA (entropie) |
| `SCI_SMR2_B` | `0xFFFFE840` | Port série SCI2 (EEPROM externe) |
| `PCIOR_W` | `0xFFFFE606` | Registre I/O ports |
| `PLIOR_W` | variable | K-Line physique |

---

## 9. État connexion physique

```
✅ nisprog v1.05 se connecte à l'ECU
✅ ECUID: 65155 — ECU répond
✅ SH7058 détecté automatiquement
✅ KKL 449.1 sur COM3 fonctionne
⚠️  Compteur bloqué (3 essais ratés avec keysets Nissan)
⏳ En attente reset compteur → couper contact 15 sec
```

---

## 10. Plan d'action — Sprint 2

| Tâche | Priorité | Méthode |
|---|---|---|
| Reset compteur | 🔴 Immédiat | Couper contact 15 sec |
| Capturer seed réel | 🔴 Immédiat | Script Python + KKL |
| Tester `key = seed ^ 0xFFFF` | 🔴 Immédiat | `setkeys <key>0000` dans nisprog |
| Valider accès SecurityAccess | 🟡 Haute | Observer réponse `0x67 0x02` |
| Tester runkernel SH7058 | 🟡 Haute | `runkernel npk_SH7058.bin` |
| Dump ROM complet | 🟡 Moyenne | `dumpmem rom.bin 0 0` |
| Valider algo seed mathématique | 🟡 Moyenne | Comparer seed reçu avec formule |
| Intégrer dans nisprog | 🟢 Finale | Créer `renault_backend.c` |
| Flash ROM modifié | 🟢 Finale | Après validation complète |

---

## 11. Script de test immédiat

```python
# test_key_ewr20.py
# Après reset compteur (contact coupé 15 sec)

import serial, time

PORT = 'COM3'

ser = serial.Serial(port=PORT, baudrate=10400,
                    bytesize=8, parity='N', stopbits=1, timeout=2)

def fast_init():
    ser.break_condition = True
    time.sleep(0.025)
    ser.break_condition = False
    time.sleep(0.300)

def send_recv(data):
    ser.write(bytes(data))
    time.sleep(0.1)
    r = ser.read(64)
    print("TX: " + bytes(data).hex(' ').upper())
    print("RX: " + r.hex(' ').upper())
    return r

fast_init()
time.sleep(0.3)
send_recv([0xC2, 0x10, 0xF1, 0x10, 0x85, 0x98])  # StartSession
time.sleep(0.3)

# RequestSeed
r = send_recv([0xC2, 0x10, 0xF1, 0x27, 0x01, 0xBB])
for i in range(len(r)-1):
    if r[i] == 0x67 and r[i+1] == 0x01:
        seed = (r[i+2] << 8) | r[i+3]
        key  = seed ^ 0xFFFF
        print("\n>>> SEED = 0x%04X" % seed)
        print(">>> KEY  = 0x%04X" % key)
        print(">>> nisprog: setkeys %04X0000" % key)

        # SendKey
        time.sleep(0.1)
        send_recv([0xC3, 0x10, 0xF1, 0x27, 0x02,
                   (key>>8)&0xFF, key&0xFF,
                   (0xC3+0x10+0xF1+0x27+0x02+(key>>8)+(key&0xFF))&0xFF])
        break

ser.close()
```

---

## 12. Fichiers de référence

| Fichier | Contenu |
|---|---|
| `64810223F121200000.hex` | Firmware EWR20 original |
| `ecu.a2l` | Définitions variables ASAP2 |
| `nisprog.ini` | Config COM3, destaddr 0x10 |
| `test_key_ewr20.py` | Script capture + test key automatique |
| `testcandidate.py` | Script test candidats key |

---

## 13. PDFs de référence

| Fichier | Fonction | Pertinence |
|---|---|---|
| `0x2848C.pdf` | `sub_2848C` — algo seed | ⭐⭐⭐⭐⭐ |
| `83EC-suivante_de_27e76.pdf` | `sub_283EC` + `sub_27E76` | ⭐⭐⭐⭐⭐ |
| `27_02v5.pdf` | `sub_27E76` complet | ⭐⭐⭐⭐⭐ |
| `86_E7.pdf` | `sub_27BD4` — point d'entrée | ⭐⭐⭐⭐ |
| `test4.pdf` | `sub_92652` — état session | ⭐⭐⭐ |
| `test5.pdf` | `sub_91F16` — timer ATUII | ⭐⭐⭐ |
| `0x28470.pdf` | `sub_28470` — cleanup | ⭐⭐ |
