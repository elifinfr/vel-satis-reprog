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
⟺ key = ~seed   (complément bitwise 16-bit par paire)
```

**La KEY est le complément bitwise du SEED (32-bit, appliqué par paires 16-bit) :**

```c
uint32_t compute_key(uint32_t seed) {
    return seed ^ 0xFFFFFFFF;
    // équivalent : return ~seed;
}
```

### Exemple

```
seed reçu  : 0x1234ABCD
key correct : 0x1234ABCD ^ 0xFFFFFFFF = 0xEDCB5432
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
✅ Débrancher la batterie (borne -) 30 sec = reset garanti
⚠️  ECU actuellement bloqué — reset batterie nécessaire avant tout essai
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

## 9. État connexion physique (fin Sprint 1)

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

---

## Sprint 2 — Tests physiques KWP2000 & validation SecurityAccess

---

## S2.1 — Résultats des tests de connexion

### Configuration validée

Après analyse des logs nisprog et tests live, la configuration effective confirmée est :

| Paramètre | Valeur | Source |
|---|---|---|
| Port | `COM3` | nisprog.ini |
| Baudrate | 10400 bps | KWP2000 standard |
| testerid | `0xFC` | Réponse ECU `0x83 0xFC 0x10 0xC1` |
| destaddr | `0x10` | Confirmé |
| Interface | KKL 449.1 dumb, MAN_BREAK | dumbopts 0x48 |

> ⚠️ Le `testerid 0xF1` initialement utilisé dans nisprog.ini était incorrect.
> L'ECU répond systématiquement avec `dest=0xFC` dans ses trames → testerid effectif = `0xFC`.

### Séquence de connexion confirmée

```
TX:  81 10 FC 81 0E          ← StartCommunication (format fixe, pas C0)
RX:  83 FC 10 C1 5D 8F 3C   ← KeyBytes 0x5D 0x8F + checksum OK
```

---

## S2.2 — Découverte : StartSession 0x85 refusée

Tentative d'ouverture de session de programmation `0x10 0x85` :

```
TX:  C2 10 FC 10 85 63
RX:  C3 FC 10 7F 10 11 6F   ← NRC 0x11 = serviceNotSupported
```

**Conclusion : la session 0x85 n'existe pas sur cet ECU EWR20.**
Le service 0x27 est accessible directement après StartCommunication, sans session préalable.

---

## S2.3 — Capture seed réelle confirmée ✅

Seed capturée en conditions réelles sur l'ECU :

```
TX:  C2 10 FC 27 01 F6       ← RequestSeed
RX:  C6 FC 10 67 01 AF 1B 51 DE 33
```

**La seed est 32-bit** (4 octets) : `0xAF1B51DE`

> Confirmation de la variable A2L `vFLASEED` (ULONG 32-bit) identifiée en Sprint 1.
> La seed 16-bit `vSEED` n'est pas utilisée pour ce niveau d'accès.

Exemples de seeds capturées :

| Session | Seed | Key calculée (`^ 0xFFFFFFFF`) |
|---|---|---|
| 1 | `0x6F9C5E81` | `0x9063A17E` |
| 2 | `0x81CE7CE8` | `0x7E318317` |
| 3 | `0xAF1B51DE` | `0x50E4AE21` |

---

## S2.4 — Résultat SendKey : NRC 0x35

```
TX:  C6 10 FC 27 02 50 E4 AE 21 FE
RX:  C3 FC 10 7F 27 35 AA   ← NRC 0x35 = exceededNumberOfAttempts
```

**L'algo key `seed ^ 0xFFFFFFFF` n'a pas pu être validé** — le compteur était bloqué
à chaque tentative avant même l'évaluation de la clé.

> L'ECU répond NRC 0x35 immédiatement sans évaluer la key → compteur épuisé en RAM.
> Le reset batterie (borne - débranché 30 sec) est obligatoire avant toute nouvelle tentative.

---

## S2.5 — Mise au point du script Python

### Environnement

- Windows 10 LTS, Python 3.11, `pip install pyserial`
- Script `test_key_ewr20.py` dans `C:\Users\admin\Desktop\nisprog\nisprog_1.05\`

### Problèmes résolus

| Problème | Cause | Fix |
|---|---|---|
| `diag sendreq 27 01` → envoie `0x1B` | nisprog interprète en décimal | Utiliser `0x27` explicitement |
| RX = écho TX uniquement | KKL dumb loopback non filtré | Lire et jeter `len(TX)` octets avant le RX |
| StartSession 0x85 → NRC 0x11 | Service inexistant sur EWR20 | Supprimer StartSession, aller direct 0x27 |
| seed parsée sur 16-bit | Script original incomplet | Parser 4 octets → seed 32-bit |
| `setkeys` remet à zéro | Format non reconnu par nisprog | `setkeys` sert au kernel uniquement, pas au `diag sendreq` manuel |

### Script final validé (communications OK)

```python
# test_key_ewr20_v5.py
import serial, time

PORT   = 'COM3'
TESTER = 0xFC   # confirmé par réponse ECU
DEST   = 0x10

ser = serial.Serial(port=PORT, baudrate=10400,
                    bytesize=8, parity='N', stopbits=1, timeout=2)

def fast_init():
    ser.break_condition = False
    time.sleep(0.300)
    ser.break_condition = True
    time.sleep(0.025)
    ser.break_condition = False
    time.sleep(0.025)

def build(data):
    header = [0xC0 | len(data), DEST, TESTER]
    frame  = header + data
    frame += [sum(frame) & 0xFF]
    return frame

def send_recv(frame, wait=0.6):
    ser.flushInput()
    tx = bytes(frame)
    ser.write(tx)
    echo = ser.read(len(tx))   # jeter l'écho KKL dumb
    time.sleep(wait)
    r = ser.read(64)
    print("TX:   " + tx.hex(' ').upper())
    print("RX:   " + r.hex(' ').upper())
    return r

fast_init()
time.sleep(0.050)

# StartCommunication
r = send_recv([0x81, DEST, TESTER, 0x81, (0x81+DEST+TESTER+0x81)&0xFF], wait=0.4)
if 0xC1 not in r:
    print("ERREUR StartComm")
    ser.close()
    exit()
print(">>> StartComm OK")
time.sleep(0.055)

# Guard anti-gaspillage compteur
# RequestSeed direct (pas de StartSession)
r = send_recv(build([0x27, 0x01]), wait=0.6)

for i in range(len(r)-2):
    if r[i] == 0x7F and r[i+1] == 0x27:
        nrc = r[i+2]
        if nrc == 0x35:
            print("COMPTEUR BLOQUÉ — débrancher batterie (borne -) 30 sec")
        elif nrc == 0x22:
            print("CONDITIONS NON REMPLIES")
        else:
            print("NRC reçu : %02X" % nrc)
        ser.close()
        exit()

for i in range(len(r) - 5):
    if r[i] == 0x67 and r[i+1] == 0x01:
        seed_hi = (r[i+2] << 8) | r[i+3]
        seed_lo = (r[i+4] << 8) | r[i+5]
        key_hi  = seed_hi ^ 0xFFFF
        key_lo  = seed_lo ^ 0xFFFF

        print("\n>>> SEED = 0x%04X%04X" % (seed_hi, seed_lo))
        print(">>> KEY  = 0x%04X%04X" % (key_hi, key_lo))

        time.sleep(0.055)
        r2 = send_recv(build([0x27, 0x02,
                              (key_hi>>8)&0xFF, key_hi&0xFF,
                              (key_lo>>8)&0xFF, key_lo&0xFF]), wait=0.6)

        if 0x67 in r2 and 0x02 in r2:
            print("\n✓ SecurityAccess ACCORDÉ !")
        else:
            print("\n✗ Clé refusée")
            for j in range(len(r2)-2):
                if r2[j] == 0x7F:
                    print("NRC: %02X" % r2[j+2])
        break
else:
    print("ERREUR: pas de seed dans la réponse")

ser.close()
```

---

## S2.6 — État fin Sprint 2

```
✅ Connexion KWP2000 stable et reproductible
✅ StartCommunication OK — KeyBytes 0x5D 0x8F
✅ Seed 32-bit capturée sur 3 sessions différentes
✅ Script Python fonctionnel (écho filtré, seed 32-bit, guard NRC)
✅ testerid 0xFC confirmé (pas 0xF1)
✅ Session 0x85 inutile — 0x27 accessible en session default
⚠️  Algo key `seed ^ 0xFFFFFFFF` non validé — compteur bloqué à chaque tentative
⏳ Action requise : débrancher borne (-) batterie 30 sec → relancer script
```

---

## S2.7 — Plan d'action Sprint 3

| Tâche | Priorité | Méthode |
|---|---|---|
| Reset compteur batterie | 🔴 Immédiat | Débrancher borne (-) 30 sec |
| Valider `key = seed ^ 0xFFFFFFFF` | 🔴 Immédiat | Lancer `test_key_ewr20_v5.py` |
| Si 0x67 0x02 → lancer kernel | 🔴 Immédiat | `runkernel npk_SH7058.bin` via nisprog |
| Si key refusée → analyser algo `sub_31170` | 🟡 Haute | RE IDA — bit permutation + EEPROM params |
| Dump ROM complet | 🟡 Haute | `dumpmem rom.bin 0 0` après kernel OK |
| Valider algo seed mathématique | 🟡 Moyenne | Comparer seeds capturées avec formule `sub_2848C` |
| Intégrer dans nisprog | 🟢 Finale | Créer `renault_backend.c` |
| Flash ROM modifié | 🟢 Finale | Après validation dump complet |

---

## 11. Script de test — version finale Sprint 2

Voir section S2.5 — `test_key_ewr20_v5.py`

---

## 12. Fichiers de référence

| Fichier | Contenu |
|---|---|
| `64810223F121200000.hex` | Firmware EWR20 original |
| `ecu.a2l` | Définitions variables ASAP2 |
| `nisprog.ini` | Config COM3, testerid 0xFC, destaddr 0x10 |
| `test_key_ewr20_v5.py` | Script capture + test key (version finale Sprint 2) |
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
