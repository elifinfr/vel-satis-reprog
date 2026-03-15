/* renault_backend.c
 * SecurityAccess pour ECU Renault EWR20 SH7058
 * Basé sur RE firmware 64810223F121200000.hex
 */

#include <stdint.h>
#include <stdio.h>
#include "stypes.h"
#include "diag.h"
#include "diag_l2.h"
#include "nisprog.h"

/* Compute seed EWR20
 * seed = ((timer_delta) + 0x2A0) >> 5 << 7
 * En pratique : seed est reçu depuis l'ECU
 * Cette fonction calcule la KEY depuis le seed reçu
 */
static uint16_t renault_compute_key(uint16_t seed) {
    /* Algo basé sur sub_31170 + params EEPROM
     * Params lus depuis EEPROM externe via SCI2
     * Stride=3, base=0x1FF0 (candidat le plus probable)
     * key_const = { 0x50, 0x00, 0x24, 0x24 }
     * À VALIDER sur ECU réel
     */
    uint16_t key = seed;

    /* Bit permutation selon flags ECU
     * sub_31170 fait un remapping bit par bit
     * basé sur l'état des paramètres session
     */

    /* Candidat 1 — stride=3 */
    key ^= 0x5024;
    key = ((key >> 8) | (key << 8)) & 0xFFFF;

    return key;
}

int renault_sid27_unlock(void) {
    uint8_t txdata[64];
    struct diag_msg nisreq = {0};
    struct diag_msg *rxmsg = NULL;
    int errval;

    /* Step 1 : RequestSeed */
    txdata[0] = 0x27;
    txdata[1] = 0x01;
    nisreq.len = 2;
    nisreq.data = txdata;

    rxmsg = diag_l2_request(global_l2_conn, &nisreq, &errval);
    if (rxmsg == NULL) return -1;

    if (rxmsg->data[0] != 0x67) {
        printf("Bad 27 01 response\n");
        diag_freemsg(rxmsg);
        return -1;
    }

    uint16_t seed = (rxmsg->data[2] << 8) | rxmsg->data[3];
    printf("Seed recu : 0x%04X\n", seed);
    diag_freemsg(rxmsg);

    /* Compute key */
    uint16_t key = renault_compute_key(seed);
    printf("Key calculee : 0x%04X\n", key);

    /* Step 2 : SendKey */
    txdata[0] = 0x27;
    txdata[1] = 0x02;
    txdata[2] = (key >> 8) & 0xFF;
    txdata[3] = key & 0xFF;
    nisreq.len = 4;

    rxmsg = diag_l2_request(global_l2_conn, &nisreq, &errval);
    if (rxmsg == NULL) return -1;

    if (rxmsg->data[0] != 0x67) {
        printf("Access DENIED — key incorrecte\n");
        diag_freemsg(rxmsg);
        return -1;
    }

    printf("Access GRANTED !\n");
    diag_freemsg(rxmsg);
    return 0;
}