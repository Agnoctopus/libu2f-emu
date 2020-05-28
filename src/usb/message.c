#include <stdlib.h>
#include <string.h>

#include "message.h"


/* Floor and ceil util */
#define FLOOR_NB(nb, m) ((nb) & ~((m) - 1))
#define CEIL_NB(nb, m) FLOOR_NB(nb + m - 1, m)


struct message *message_new(const struct packet_init *init_packet)
{
    /* Check size */
    uint16_t bcnt = packet_init_get_bcnt(init_packet);
    if (bcnt > MSG_MAX_SIZE)
        return NULL;

    /* Allocate */
    struct message *message = malloc(sizeof(struct message));
    if (message == NULL)
        return NULL;

    /* Message informations */
    message->cid = init_packet->cid;
    message->cmd = init_packet->cmd;
    message->bcnt = bcnt;

    /* Size */
    if (bcnt > PACKET_INIT_DATA_SIZE)
        message->size = PACKET_INIT_DATA_SIZE;
    else
        message->size = bcnt;

    /* Capacity */
    if (bcnt > 0)
        message->capacity = CEIL_NB(bcnt, MSG_DEF_CAP);
    else
        message->capacity = MSG_DEF_CAP;

    /* Data buffer allocation */
    uint8_t *data = malloc(message->capacity);
    if (data == NULL)
    {
        /* Release */
        free(message);
        return NULL;
    }
    memcpy(data, init_packet->data, message->size);
    message->data = data;

    return message;
}

struct message *message_new_blank(uint32_t cid, uint8_t cmd)
{
    /* Init packet */
    struct packet_init init_packet;
    init_packet.cid = cid;
    init_packet.cmd = cmd;
    packet_init_set_bcnt(&init_packet, 0);

    /* Delegate */
    return message_new(&init_packet);
}


struct message *message_new_from_data(uint32_t cid, uint8_t cmd,
        const uint8_t *data, size_t size)
{
    /* Instantiate the message */
    struct message *message = message_new_blank(cid, cmd);
    if (message == NULL)
        return NULL;

    /* Add data */
    if (!message_add_data(message, data, size))
    {
        /* Release */
        message_free(message);
        return NULL;
    }
    return message;
}

bool message_add_data(struct message *message,
        const uint8_t *data, size_t size)
{
    /* Check size */
    uint16_t size_new = message->size + size;
    if (size_new > MSG_MAX_SIZE)
        return false;

    /* Check capacity */
    if (size_new > message->capacity)
    {
        /* Expand */
        uint16_t cap_new = CEIL_NB(size_new, MSG_DEF_CAP);
        uint8_t *data_new = realloc(message->data, cap_new);
        if (data_new == NULL)
            return false;

        /* Update */
        memcpy(data_new, data, message->size);
        message->capacity = cap_new;
    }

    /* Add data */
    memcpy(message->data + message->size, data, size);

    /* Update */
    message->size = size_new;
    message->bcnt += size;

    return true;
}

bool message_add_part(struct message *message,
        const struct packet_cont *cont_packet)
{
    /* Check cid */
    if (cont_packet->cid != message->cid)
        return false;

    /* Get current seq */
    uint8_t seq = 0;
    if (message->bcnt > PACKET_INIT_DATA_SIZE)
        seq = (message->bcnt - PACKET_INIT_DATA_SIZE)
            / PACKET_CONT_DATA_SIZE;

    /* Check seq */
    if (seq != cont_packet->seq)
        return false;

    /* Compute data size of the packet */
    uint16_t size_cont = PACKET_CONT_DATA_SIZE;
    if (message->size + size_cont > message->bcnt)
        size_cont = message->bcnt - message->size;

    /* Check cont size */
    if (size_cont == 0)
        return false;

    /* Add data */
    memcpy(message->data + message->size,
        cont_packet->data, size_cont);
    message->size += size_cont;

    return true;
}

void message_free(struct message *message)
{
    free(message->data);
    free(message);
}