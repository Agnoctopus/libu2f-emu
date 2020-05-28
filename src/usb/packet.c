#include <err.h>
#include <stdlib.h>
#include <string.h>

#include "cmd.h"
#include "packet.h"
#include "transaction.h"



struct packet_init *packet_init_new(uint32_t cid, uint8_t cmd,
        uint16_t bcnt)
{
    /* Allocate */
    struct packet_init *packet = calloc(1,
        sizeof(struct packet_init));
    if (packet == NULL)
        return NULL;

    /* Init */
    packet->cid = cid;
    packet->cmd = cmd;
    packet_init_set_bcnt(packet, bcnt);

    return packet;
}

struct packet_cont *packet_cont_new(uint32_t cid, uint8_t seq)
{
    /* Allocate */
    struct packet_cont *packet = calloc(1,
        sizeof(struct packet_cont));
    if (packet == NULL)
        return NULL;

    /* Init */
    packet->cid = cid;
    packet->seq = seq;

    return packet;
}

void *packet_copy(const void *packet)
{
    /* Allocate */
    void *packet_cpy = malloc(PACKET_SIZE);
    if (packet_cpy == NULL)
        return NULL;

    /* Copy */
    memcpy(packet_cpy, packet, PACKET_SIZE);

    return packet_cpy;
}