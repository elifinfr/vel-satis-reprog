# Compte rendu RE — ECU Renault EWR20 SH7058 VQ35DE

---

## Sprint 1 — Reverse Engineering firmware 64810223F121200000.hex

### 1. Contexte et matériel

| | |
|---|---|
| **ECU cible** | Denso EWR20 — Renault Espace IV / Laguna III / Vel Satis — moteur VQ35DE 3.5 V6 |
| **MCU** | Hitachi SH7058 (SH-2A, Big-Endian, 1MB FLASH interne) |
| **Firmware** | `64810223F121200000.hex` — Intel HEX, base `0x00000400` |
| **Projet ASAP2** | TK_X91_EUR_VC, version 7V4YHZEB2, généré par RB4-ASAP2 GENERATOR (commun Nissan/Renault) |
| **Outils utilisés** | IDA Pro (SH2A, Big-Endian), nisprog v1.05, KKL 449.1 |

### 2. Architecture mémoire SH7058

| Zone | Adresse | Contenu |
|---|---|---|
| FLASH interne | `0x00000000–0x000FFFFF` | Code firmware |
| RAM interne | `0xFFFF0000–0xFFFFFFFF` | Variables runtime |
| Registres hardware | `0xFFFFE000+` | DMAC, SCI, ATU, PCIOR |

### 3. Variables A2L identifiées

| Nom A2L | Type | Adresse RAM | Description |
|---|---|---|---|
| `vSEED` | UWORD | `0xFFFFB644` | Seed 16-bit (KWP standard) |
| `vFLASEED` | ULONG | `0xFFFFB5F8` | Seed 32-bit (accès FLASH) |
| `tSADT` | UBYTE | `0xFFFF44BA` | Délai seed FLASH |
| `tSADT_S` | UBYTE | `0xFFFF45B0` | Délai seed sécurité |

### 4. Hiérarchie des fonctions KWP2000 service 0x27

```
sub_27BD4  ← point d'entrée principal KWP dispatcher
│
├── sub_29FF8        init hardware PLIOR (K-Line physique)
├── sub_283EC        orchestrateur seed
│   ├── sub_6F61C    getter paramètre EEPROM (avec retry)
│   │   └── sub_6F0E8  driver IIC lecture EEPROM externe
│   ├── sub_2848C    calcul seed (algo mathématique)
│   └── sub_70554    driver SCI2 transmission K-Line
│
├── sub_27C80        dispatcher sous-services 0x27
│   ├── sub_2851C    vérification KEY
│   └── sub_27E76    handler complet 0x27 (RequestSeed + SendKey)
│       ├── sub_6F61C  lecture params NVM 0x1FF3→0x1FF8, 0x1FBC, 0x1FBE
│       ├── sub_6F0E8  lecture params KEY 0x1FB8→0x1FBB
│       └── sub_70554  transmission réponse
│
└── sub_31170        construction KEY (bit permutation + EEPROM)
    └── sub_6ED78    driver IIC écriture/lecture EEPROM
```

### 5. Algorithme SEED — Prouvé par RE

**Source d'entropie**
```
dword_227A0 = { 0xFFFF9C6C, 0xFFFF9F48 }
```
Deux adresses RAM pointant vers des compteurs libres ATU (Advanced Timer Unit) du SH7058 — valeur pseudo-aléatoire dépendant du timing exact de la requête.

**Fonction sub_2848C — Algo seed complet**
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

**Validation des paramètres NVM avant génération seed**
```
sub_283EC vérifie :
  param[0x1FFF] ∈ {0x00, 0xAA, 0x55}  → type d'accès autorisé
  param[0x1FF0] ∈ {0x00, 0x55, 0xFF}  → type d'accès secondaire

Si OK → appelle sub_2848C → envoie seed via sub_70554
```

### 6. Algorithme KEY — ✅ RÉSOLU

**sub_2851C — Fonction de vérification KEY (découverte finale)**

La vérification utilise un XOR avec 0xFFFF pour chaque paire received/stored :

```c
int verify_key(void) {
    // GBR base = 0xFFFFB52C
    // Retourne 0x00 = SUCCÈS, 0xFF = ÉCHEC

    // Vérification 1
    uint16_t r = *(uint16_t*)(0xFFFF9FEC + 0x9E*2);  // clé reçue du tester
    uint16_t s = *(uint16_t*)(GBR + 0xDA);             // clé calculée ECU
    if ((r ^ s) != 0xFFFF) return 0xFF;

    // Vérifications 2 à 7 — même pattern XOR 0xFFFF
    // sur différentes paires d'adresses GBR et RAM
    // ...

    return 0x00;  // SUCCÈS
}
```

**🔑 Algorithme KEY — Formule finale**
```
(received_key ^ stored_key) == 0xFFFF
⟺ key = ~seed   (complément bitwise 16-bit par paire)
```

```c
uint32_t compute_key(uint32_t seed) {
    return seed ^ 0xFFFFFFFF;
    // équivalent : return ~seed;
}
```

**Exemple**
```
seed reçu   : 0x1234ABCD
key correct : 0x1234ABCD ^ 0xFFFFFFFF = 0xEDCB5432
```

### 7. Compteur de tentatives — Mécanisme RE

**Localisation** : `sub_27C80 @ 0x27CFC–0x27D0A`

**Fonctionnement — Système à états, pas compteur numérique**
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

**Reset du compteur**
- ✅ Flag en RAM volatile → disparaît à la coupure d'alimentation
- ✅ Contact coupé 15 secondes = reset complet
- ✅ Débrancher la batterie (borne -) 30 sec = reset garanti
- ⚠️ ECU actuellement bloqué — reset batterie nécessaire avant tout essai

### 8. Registres hardware utilisés

| Registre | Adresse | Rôle |
|---|---|---|
| ATUII_ICR0DH_W | `0xFFFF9C54` | Timer — source entropie seed |
| DMAC_DMAOR_W | `0xFFFFE410` | État DMA (entropie) |
| SCI_SMR2_B | `0xFFFFE840` | Port série SCI2 (K-Line) |
| IIC_ICCR1 | `0xFFFFF73A` | Module IIC — EEPROM externe |
| PCIOR_W | `0xFFFFE606` | Registre I/O ports |

### 9. État connexion physique (fin Sprint 1)

- ✅ nisprog v1.05 se connecte à l'ECU
- ✅ ECUID: 65155 — ECU répond
- ✅ SH7058 détecté automatiquement
- ✅ KKL 449.1 sur COM3 fonctionne
- ⚠️ Compteur bloqué (3 essais ratés avec keysets Nissan)
- ⏳ En attente reset compteur → couper contact 15 sec

---

## Sprint 2 — Tests physiques KWP2000 & validation SecurityAccess

### S2.1 — Résultats des tests de connexion

**Configuration validée**

| Paramètre | Valeur | Source |
|---|---|---|
| Port | COM3 | nisprog.ini |
| Baudrate | 10400 bps | KWP2000 standard |
| testerid | 0xFC | Réponse ECU `0x83 0xFC 0x10 0xC1` |
| destaddr | 0x10 | Confirmé |
| Interface | KKL 449.1 dumb, MAN_BREAK | `dumbopts 0x48` |

> ⚠️ Le testerid `0xF1` initialement utilisé dans nisprog.ini était incorrect. L'ECU répond systématiquement avec `dest=0xFC` dans ses trames → testerid effectif = `0xFC`.

**Séquence de connexion confirmée**
```
TX:  81 10 FC 81 0E          ← StartCommunication (format fixe, pas C0)
RX:  83 FC 10 C1 5D 8F 3C   ← KeyBytes 0x5D 0x8F + checksum OK
```

### S2.2 — Découverte : StartSession 0x85 refusée

```
TX:  C2 10 FC 10 85 63
RX:  C3 FC 10 7F 10 11 6F   ← NRC 0x11 = serviceNotSupported
```

> Conclusion : la session 0x85 n'existe pas sur cet ECU EWR20. Le service 0x27 est accessible directement après StartCommunication, sans session préalable.

### S2.3 — Capture seed réelle confirmée ✅

```
TX:  C2 10 FC 27 01 F6       ← RequestSeed
RX:  C6 FC 10 67 01 AF 1B 51 DE 33
```

La seed est 32-bit (4 octets) : `0xAF1B51DE`

**Exemples de seeds capturées**

| Session | Seed | Key calculée (^ 0xFFFFFFFF) |
|---|---|---|
| 1 | `0x6F9C5E81` | `0x9063A17E` |
| 2 | `0x81CE7CE8` | `0x7E318317` |
| 3 | `0xAF1B51DE` | `0x50E4AE21` |

### S2.4 — Résultat SendKey : NRC 0x35

```
TX:  C6 10 FC 27 02 50 E4 AE 21 FE
RX:  C3 FC 10 7F 27 35 AA   ← NRC 0x35 = exceededNumberOfAttempts
```

> L'ECU répond NRC 0x35 immédiatement sans évaluer la key → compteur épuisé en RAM. Le reset batterie est obligatoire avant toute nouvelle tentative. **Ce NRC 0x35 provient d'un verrou EEPROM, pas d'un compteur RAM seul** (cf. Sprint 3, S3.1).

### S2.5 — Script Python version finale

**`test_key_ewr20_v5.py`** — Script complet : StartCommunication → RequestSeed → SendKey → affichage réponse 0x67 ou NRC.

### S2.6 — Plan Sprint 3

| Tâche | Priorité | Méthode |
|---|---|---|
| Analyser NRC 0x35 path ASM | 🔴 Immédiat | Trace sub_27C80 |
| Identifier chip EEPROM exact | 🔴 Immédiat | Analyse registres firmware |
| Vérifier checksum EEPROM | 🔴 Immédiat | Scan pattern firmware |
| Analyser nisprog capabilities | 🟡 Haute | Code source nisprog-master |
| Procédure reset physique EEPROM | 🟡 Haute | CH341A + SOIC-8 clip |

---

## Sprint 3 — Analyse NRC 0x35, EEPROM type, sécurité checksum, reset physique

### S3.1 — Trace ASM NRC 0x35 : chemin prouvé

**Analyse de sub_27C80 via `trace_nrc35.py`**

Le NRC 0x35 (`exceededNumberOfAttempts`) est déclenché par une **valeur en EEPROM**, pas seulement par un compteur RAM. Chemin complet tracé en assembleur SH2A :

```
0x27CE2: MOV.L @PC, R4       ; R4 = 0x1FFF  (adresse EEPROM)
0x27CE8: JSR @R5              ; appel sub_6F61C (lecture EEPROM avec retry)
0x27CEA: NOP
         ; R2 = valeur EEPROM[0x1FFF]
0x27D04: TST R2, R2           ; test si R2 == 0x00
0x27D06: BT  0x27DXX          ; si 0x00 → accès autorisé (branche succès)
0x27D08: CMP/EQ #0xAA, R0    ; test si 0xAA (seed active)
0x27D0A: BF  →NRC_0x35        ; si ni 0x00 ni 0xAA → NRC 0x35
```

**Signification des valeurs EEPROM[0x1FFF]**

| Valeur | État | Comportement |
|---|---|---|
| `0x00` | Reset (débloqué) | Accès SecurityAccess autorisé |
| `0xAA` | Seed active | Accès autorisé (phase intermédiaire) |
| `0x55` | Verrouillé | NRC 0x35 immédiat, key non évaluée |
| Autre | Inconnu | NRC 0x35 par défaut |

**Adresse anti-rejeu** : `0x1FFE` lu à `0x27D44` — comparé à la seed précédente pour empêcher le rejeu. Ne pas modifier.

**Script** : `trace_nrc35.py` — disassemble sub_27C80 (220 instructions) + sub_6F0E8 + scan NRC 0x35 dans 0x27000–0x28500.

### S3.2 — Identification EEPROM : AT24C64 (I2C) — PAS 93C66 (SPI)

**Confusion dans les sources externes** : le backup ecufix.info nomme le fichier "93c66" mais l'analyse firmware prouve le contraire.

**Preuves firmware (via `check_eeprom_type.py`)**

| Indicateur | Résultat | Conclusion |
|---|---|---|
| Références registre IIC `0xFFFFF73A` | **76 occurrences** | Module IIC hardware actif |
| Références SCI2 `0xFFFFE840` | 0 pour EEPROM | SCI2 = K-Line uniquement |
| Littéral pool sub_6F0E8 | `[0x6ECA8] = 0xFFFFF73A` | Driver EEPROM = IIC |
| Adresse max utilisée `0x1FFF` | 8191 decimal | Impossible sur 93C66 (max 511) |
| Adresse max utilisée `0x1FFF` | 8191 decimal | Compatible AT24C64 (max 8191) |

**Conclusion définitive** : chip = **AT24C64** (Atmel/Microchip, I2C, 8 Ko, adresse 0x50).

**Protocole I2C AT24C64 — séquence d'écriture**
```
START
  0xA0        ← adresse device (0x50 << 1, W)
  0x1F        ← MSB adresse mot (0x1FFF >> 8)
  0xFF        ← LSB adresse mot
  0x00        ← donnée à écrire
STOP
```
Attendre 5ms (write cycle time) avant accès suivant.

**Script** : `check_eeprom_type.py`

### S3.3 — Analyse checksum EEPROM : aucun risque confirmé

**Résultat** : **zéro instruction DT** dans l'intégralité du firmware 1Mo.

L'instruction DT (Decrement and Test) est le moteur universel des boucles for/while en SH2A. Son absence totale prouve qu'il n'existe aucune boucle d'accumulation pouvant calculer un checksum sur une plage EEPROM.

**Analyses effectuées (via `check_eeprom_checksum.py` + `check_csum_detail.py`)**

| Test | Résultat |
|---|---|
| Scan DT (4400x) dans tout le firmware | 0 occurrences |
| Pattern ADD Rm,Rn + CMP/EQ près d'une lecture EEPROM | 0 patterns détectés |
| Lecture EEPROM[0x1FFF] dans sub_27C80 | Octet seul, non additionné |
| Lecture EEPROM[0x1FF0-0x1FF2] | Octets seuls, flags indépendants |

**Tableau de sécurité des modifications**

| Adresse | Rôle | Modifier ? | Risque |
|---|---|---|---|
| `0x1FFF` | Verrou principal NRC 0x35 | ✅ Oui → `0x00` | Aucun |
| `0x1FF0` | Etat secondaire | ✅ Oui → `0x00` | Aucun |
| `0x1FF1` | Flag secondaire 1 | ✅ Oui → `0x00` | Aucun |
| `0x1FF2` | Flag secondaire 2 | ✅ Oui → `0x00` | Aucun |
| `0x1FFE` | Seed anti-rejeu | ❌ Non | Reset seed = OK mais inutile |
| `0x1FB8-0x1FBF` | Paramètres KEY algo | ❌ Non | Casse l'algorithme KEY |
| `0x1FF3-0x1FF8` | Params NVM seed | ❌ Non | Affecte génération seed |

### S3.4 — Analyse nisprog : dead-end confirmé

**nisprog ne peut pas accéder à l'EEPROM sans SecurityAccess valide.**

Analyse complète du source `nisprog-master/` :

| Commande nisprog | Résultat | Raison |
|---|---|---|
| `runkernel npk_SH7058.bin` | Nécessite SID 0x27 | `cmd_runkernel()` appelle SecurityAccess |
| `sprunkernel` | Idem | Même dépendance |
| `dumpmem rom.bin 0 0` | Nécessite kernel | Kernel = SID 0xBD |
| `dumpmem eep.bin 0 0 eep` | Nécessite kernel | Utilise `SID_DUMP_EEPROM 0x00` |
| `SID_WMBA 0x3D` (kernel) | RAM uniquement | Pas d'accès EEPROM hardware |

**Conclusion** : sans SecurityAccess → pas de kernel → pas de dump/write EEPROM via nisprog.
La seule solution est l'accès physique direct au chip EEPROM.

### S3.5 — Procédure reset physique EEPROM (AT24C64)

#### Matériel requis

| Outil | Usage |
|---|---|
| CH341A programmer USB | Lecture/écriture I2C/SPI |
| Clip SOIC-8 (pince crocodile) | Connexion sans déssoudage |
| AsProgrammer | Logiciel Windows pour CH341A |
| Pince coupante / tournevis | Accès ECU |

#### Étapes

1. **Ouvrir le boitier ECU** — retirer les vis, dégager le PCB.

2. **Localiser le chip EEPROM** — SOIC-8, marqué AT24C64 ou compatible. Situé près du connecteur ECU.

3. **Brancher le clip SOIC-8** sur le chip (ECU hors tension).

4. **Connecter le CH341A** en mode I2C :
   ```
   CH341A pin 1 (SDA) → EEPROM pin 5 (SDA)
   CH341A pin 2 (SCL) → EEPROM pin 6 (SCL)
   CH341A VCC (3.3V)  → EEPROM pin 8 (VCC)
   CH341A GND         → EEPROM pin 4 (GND)
   ```
   > Déconnecter le connecteur ECU du véhicule pendant l'opération.

5. **Lire le dump original** dans AsProgrammer :
   - Chip : AT24C64 (ou 24C64)
   - Adresse I2C : 0x50
   - Cliquer "Lire" → sauvegarder `eeprom_original.bin`

6. **Vérifier le dump** :
   ```
   python verify_eeprom_dump.py eeprom_original.bin
   ```

7. **Appliquer le fix** :
   ```
   python fix_eeprom.py eeprom_original.bin eeprom_fixed.bin
   ```

8. **Flasher le fichier corrigé** dans AsProgrammer :
   - Charger `eeprom_fixed.bin`
   - Cliquer "Écrire"
   - Vérifier avec "Lire + Comparer"

9. **Remonter l'ECU**, reconnecter au véhicule.

10. **Tester SecurityAccess** avec `test_key_ewr20_v5.py` :
    ```
    python test_key_ewr20_v5.py
    ```
    Résultat attendu : `0x67 0x02` (positive response) au lieu de NRC 0x35.

### S3.6 — État fin Sprint 3

- ✅ Chemin NRC 0x35 prouvé par ASM — source = EEPROM[0x1FFF] = 0x55
- ✅ Chip EEPROM identifié = AT24C64 (I2C, 8Ko) — 93C66 exclu
- ✅ Absence totale de checksum EEPROM prouvée — modification sans risque
- ✅ nisprog dead-end confirmé — accès physique obligatoire
- ✅ Procédure physique documentée — CH341A + clip SOIC-8
- ✅ Scripts `fix_eeprom.py` et `verify_eeprom_dump.py` prêts
- ⏳ Reset physique pas encore exécuté (matériel à acquérir)

### S3.7 — Plan Sprint 4

| Tâche | Priorité | Méthode |
|---|---|---|
| Acquérir CH341A + clip SOIC-8 | 🔴 Immédiat | Amazon/AliExpress |
| Dump EEPROM original | 🔴 Immédiat | AsProgrammer + clip |
| Vérifier dump avec `verify_eeprom_dump.py` | 🔴 Immédiat | Python |
| Appliquer `fix_eeprom.py` | 🔴 Immédiat | Python |
| Reflasher AT24C64 | 🔴 Immédiat | AsProgrammer |
| Tester SecurityAccess → 0x67 0x02 | 🔴 Validation | `test_key_ewr20_v5.py` |
| Si OK → runkernel + dump ROM | 🟡 Haute | nisprog |
| Analyser ROM modifiable (calibration) | 🟢 Finale | IDA Pro |

---

## Fichiers du projet

| Fichier | Sprint | Contenu |
|---|---|---|
| `64810223F121200000.hex` | S1 | Firmware EWR20 original |
| `firmware_ewr20.bin` | S1 | Firmware converti en binaire (base 0x400) |
| `ecu.a2l` | S1 | Définitions variables ASAP2 |
| `nisprog.ini` | S2 | Config COM3, testerid 0xFC, destaddr 0x10 |
| `test_key_ewr20_v5.py` | S2 | Script capture seed + test key (version finale) |
| `trace_nrc35.py` | S3 | Disassembler SH2A — trace chemin NRC 0x35 |
| `check_eeprom_type.py` | S3 | Prouve AT24C64 I2C vs 93C66 SPI |
| `check_eeprom_checksum.py` | S3 | Scan absence checksum EEPROM |
| `check_csum_detail.py` | S3 | Analyse détaillée patterns checksum |
| `fix_eeprom.py` | S3 | Applique le fix sur dump EEPROM |
| `verify_eeprom_dump.py` | S3 | Vérifie dump avant/après flash |

---

## PDFs de référence IDA Pro

| Fichier | Fonction | Pertinence |
|---|---|---|
| `0x2848C.pdf` | sub_2848C — algo seed | ⭐⭐⭐⭐⭐ |
| `83EC-suivante_de_27e76.pdf` | sub_283EC + sub_27E76 | ⭐⭐⭐⭐⭐ |
| `27_02v5.pdf` | sub_27E76 complet | ⭐⭐⭐⭐⭐ |
| `86_E7.pdf` | sub_27BD4 — point d'entrée | ⭐⭐⭐⭐ |
| `test4.pdf` | sub_92652 — état session | ⭐⭐⭐ |
| `test5.pdf` | sub_91F16 — timer ATUII | ⭐⭐⭐ |
| `0x28470.pdf` | sub_28470 — cleanup | ⭐⭐ |
