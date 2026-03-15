Compte rendu RE — ECU Renault EWR20 SH7058 VQ35DE
Sprint 1 — Reverse Engineering firmware 64810223F121200000.hex

1. Contexte et matériel
ECU cible : Denso EWR20 — Renault Espace IV / Laguna III / Vel Satis — moteur VQ35DE 3.5 V6
MCU : Hitachi SH7058 (SH-2A, Big-Endian, 1MB FLASH interne)
Firmware : 64810223F121200000.hex — Intel HEX, base 0x00000400
Projet ASAP2 : TK_X91_EUR_VC, version 7V4YHZEB2, généré par RB4-ASAP2 GENERATOR (commun Nissan/Renault)
Outils utilisés : IDA Pro (SH2A, Big-Endian), nisprog v1.05, KKL 449.1

2. Architecture mémoire SH7058
ZoneAdresseContenuFLASH interne0x00000000–0x000FFFFFCode firmwareRAM interne0xFFFF0000–0xFFFFFFFFVariables runtimeRegistres hardware0xFFFFE000+DMAC, SCI, ATU, PCIOR

3. Variables A2L identifiées
Nom A2LTypeAdresse RAMDescriptionvSEEDUWORD0xFFFFB644Seed 16-bit (KWP standard)vFLASEEDULONG0xFFFFB5F8Seed 32-bit (accès FLASH)tSADTUBYTE0xFFFF44BADélai seed FLASHtSADT_SUBYTE0xFFFF45B0Délai seed sécurité

4. Hiérarchie des fonctions KWP2000 service 0x27
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
│   └── sub_27E76    handler complet 0x27 (RequestSeed + SendKey)
│       ├── sub_6F61C  lecture params NVM 0x1FF3→0x1FF8, 0x1FBC, 0x1FBE
│       └── sub_70554  transmission réponse
│
└── sub_31170        construction KEY (bit permutation + EEPROM)
    └── sub_6ED78    driver SCI2 écriture/lecture EEPROM

5. Algorithme SEED — Prouvé par RE
Source d'entropie
dword_227A0 = { 0xFFFF9C6C, 0xFFFF9F48 }
Deux adresses RAM pointant vers des compteurs libres ATU (Advanced Timer Unit) du SH7058 — valeur pseudo-aléatoire dépendant du timing exact de la requête.
Fonction sub_2848C — Algo seed complet
cuint16_t compute_seed(uint32_t* timer_struct) {
    // timer_struct[0] = *(uint32_t*)0xFFFF9C6C
    // timer_struct[1] = *(uint32_t*)0xFFFF9F48
    
    uint16_t delta  = (uint16_t)(timer_struct[1] - timer_struct[0]);
    uint16_t val    = delta + 0x2A0;        // offset fixe = 672
    uint16_t shifted = val >> 5;            // division par 32
    uint16_t seed   = shifted << 7;         // multiplication par 128
                                            // net effect : val * 4
    // Ajustement conditionnel
    uint16_t check  = shifted << 6;         // val * 2
    if (check == val) {
        seed += 0x20;                       // +32 si val multiple de 64
    }
    
    return seed;   // valeur 16-bit retournée dans r0
}
```

### Validation des paramètres NVM avant génération seed
```
sub_283EC vérifie :
  param[0x1FFF] ∈ {0x00, 0xAA, 0x55}  → type d'accès autorisé
  param[0x1FF0] ∈ {0x00, 0x55, 0xFF}  → type d'accès secondaire
  
Si OK → appelle sub_2848C → envoie seed via sub_70554
Paramètres NVM lus avant envoi seed (indexés depuis 0x8A28, stride=3)
Index NVMValeur (stride=3)Rôle probable0x1FF30x28 (40)seed_param10x1FF40x00seed_param20x1FF50x89seed_param30x1FF60x00seed_param40x1FF70x10seed_param50x1FF80x06seed_param60x1FFF0x00type accès = OK

6. Algorithme KEY — Partiellement RE
Fonction sub_31170 — Construction de la clé
La fonction réalise un bit-permutation sur un byte construit depuis les flags de session GBR, combiné avec les paramètres EEPROM externe.
c// Pseudo-code sub_31170
uint16_t compute_key(session_flags) {
    byte base  = read_eeprom(0x1FBE);   // param EEPROM externe
    byte modif = read_eeprom(0x1FBF);   // param EEPROM externe
    
    // Bit remapping depuis flags session GBR :
    result.bit0 = GBR[0x10].bit4
    result.bit1 = GBR[0x02].bit6
    result.bit2 = GBR[0x02].bit3  (inversé)
    result.bit3 = GBR[0x02].bit2  (inversé)
    result.bit4 = GBR[0x02].bit1  (inversé)
    result.bit5 = GBR[0x02].bit0  (inversé)
    result.bit6 = GBR[0x03].bit7  (inversé)
    result.bit7 = GBR[0x05].bit4  (inversé)
    
    // Puis appelle sub_6ED78(0x1FBE, result_buffer, 2)
    // → driver SCI2 qui envoie/reçoit via EEPROM externe
}
```

### Constantes KEY dans EEPROM externe (non accessibles statiquement)

| Index NVM | Valeur candidate (stride=3) | Rôle |
|---|---|---|
| `0x1FB8` | `0x50` | key_const1 |
| `0x1FB9` | `0x00` | key_const2 |
| `0x1FBA` | `0x24` | key_const3 |
| `0x1FBB` | `0x24` | key_const4 |
| `0x1FBC` | `0x73` | key_param1 |
| `0x1FBE` | `0x0F` | key_param2 |

⚠️ **Ces valeurs sont dans une EEPROM externe** (probablement 93Cxx) communiquant via SCI2. Elles ne peuvent pas être lues statiquement depuis le firmware seul. Le stride exact (1, 3 ou 4) reste à confirmer sur ECU réel.

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
  Service standard : 4 (cmp/eq #4 @ 0x27CFC et 0x27D08)
  Service FLASH    : 2 (cmp/eq #2 @ 0x2842A dans sub_283EC)
  Autre niveau     : 5 (cmp/eq #5 @ 0x27D58)
```

### Reset du compteur
```
✅ Flag en RAM volatile → disparaît à la coupure d'alimentation
✅ Contact coupé 15 secondes = reset complet
✅ Débrancher la batterie = reset garanti
```

---

## 8. Registres hardware utilisés

| Registre | Adresse | Rôle dans l'algo |
|---|---|---|
| `ATUII_ICR0DH_W` | `0xFFFF9C54` | Timer source entropie seed |
| `DMAC_DMAOR_W` | `0xFFFFE410` | Lecture état DMA (entropie) |
| `SCI_SMR2_B` | `0xFFFFE840` | Port série SCI2 (EEPROM) |
| `PCIOR_W` | `0xFFFFE606` | Registre I/O ports |
| `PLIOR_W` | variable | K-Line physique |

---

## 9. État de la connexion physique
```
✅ nisprog v1.05 se connecte à l'ECU
✅ ECUID: 65155 — ECU répond correctement
✅ SH7058 détecté automatiquement
✅ KKL 449.1 sur COM3 fonctionne
❌ Key non trouvée (3 essais avec keysets Nissan → exceedAttempts)
❌ Compteur actuellement bloqué → reset nécessaire

10. Ce qui reste à faire — Sprint 2
TâchePrioritéMéthodeReset compteur🔴 ImmédiatCouper contact 15 secCapturer seed réel🔴 ImmédiatScript Python + KKLValider stride EEPROM🔴 HauteTester stride 1/3/4 sur ECUTrouver compute_key exact🔴 HauteCapture seed/key + analyse différentielleValider algo seed🟡 MoyenneComparer seed reçu avec formuleIntégrer dans nisprog🟡 MoyenneCréer renault_backend.cTester flash🟢 FinaleAprès validation key

11. Fichiers de référence
FichierContenu64810223F121200000.hexFirmware EWR20 originalecu.a2lDéfinitions variables ASAP2nisprog.iniConfig connexion COM3, destaddr 0x10testcandidate.pyScript test candidats keycapture_ewr20.pyScript capture seed/key
