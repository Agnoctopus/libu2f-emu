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
    message->seq_send = PACKET_CONT_MAX_SEQ + 1;

    /* Size */
    uint16_t size = bcnt;
    if (bcnt > PACKET_INIT_DATA_SIZE)
        size = PACKET_INIT_DATA_SIZE;

    /* Capacity */
    uint16_t capacity = MSG_DEF_CAP;
    if (bcnt > 0)
        capacity = CEIL_NB(bcnt, PAYLOAD_DEF_CAP);

    /* Payload instantation */
    struct payload *payload = payload_new_with_capacity(capacity);
    if (payload == NULL)
    {
        /* Release */
        free(message);
        return NULL;
    }

    /* Add init packet content */
    payload_add_data(payload, init_packet->data, size);

    /* Link payload */
    message->payload = payload;

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
    uint16_t size_new = message->payload->size + size;
    if (size_new > MSG_MAX_SIZE)
        return false;

    /* Add data */
    if (!payload_add_data(message->payload, data, size))
        return false;
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
    if (message->payload->size + size_cont > message->bcnt)
        size_cont = message->bcnt - message->payload->size;

    /* Check cont size */
    if (size_cont == 0)
        return false;

    /* Add data */
    return payload_add_data(message->payload,
            cont_packet->data, size_cont);
}

bool message_next_packet(struct message *message, void **packet_ref)
{
    /* Payload */
    struct payload *payload = message->payload;

    /* Init packet */
    if (message->seq_send == PACKET_CONT_MAX_SEQ + 1)
    {
        /* Allocate a new packet init */
        struct packet_init *packet = packet_init_new(message->cid,
                message->cmd, message->bcnt);
        if (packet == NULL)
            return true;

        /* Compute payload size */
        size_t packet_payload_size = PACKET_INIT_DATA_SIZE;
        if (payload->size <= PACKET_INIT_DATA_SIZE)
            packet_payload_size = payload->size;

        /* Copy data */
        memcpy(packet->data, payload->data, packet_payload_size);

        /* Packet ref */
        *packet_ref = packet;

        /* Last packet */
        if (payload->size == packet_payload_size)
            return false;

        /* Set next seq to 0 */
        message->seq_send = 0;
        return true;
    }
    /* Cont paket */
    struct packet_cont *packet = packet_cont_new(message->cid,
            message->seq_send);
    if (packet == NULL)
        return true;

    /* Compute the offset */
    uint16_t offset = PACKET_INIT_DATA_SIZE
            + message->seq_send * PACKET_CONT_DATA_SIZE;

    /* Compute packet size */
    size_t packet_payload_size = PACKET_CONT_DATA_SIZE;
    if (offset + packet_payload_size >= payload->size)
        packet_payload_size = payload->size - offset;

    /* Copy data */
    memcpy(packet->data,
            payload->data + offset, packet_payload_size);

    /* Packet ref */
    *packet_ref = packet;


    /* Last packet */
    if (payload->size == offset + packet_payload_size)
    {
        message->seq_send = PACKET_CONT_MAX_SEQ + 1;
        return false;
    }

    /* Increment seq */
    ++message->seq_send;
    return true;
}

void message_free(struct message *message)
{
    payload_free(message->payload);
    free(message);
}