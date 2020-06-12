#ifndef MESSAGE_H
#define MESSAGE_H

#include <stdint.h>

#include "packet.h"
#include "payload.h"


/* bit macro */
#define BIT(x) (1 << (x))

/* Packed macro */
#define __packed __attribute__((__packed__))

/**
** \brief The default capacity of a message
*/
#define MSG_DEF_CAP 1024
#define MSG_MAX_SIZE ((PACKET_CONT_MAX_SEQ * PACKET_CONT_DATA_SIZE) \
        + PACKET_INIT_DATA_SIZE)

/**
**  \brief Message representation.
*/
struct message
{
    /* Informations */
    uint32_t cid; /**< Channel ID */
    uint8_t cmd; /**< Command */
    uint16_t bcnt; /**< Protocol bitcount */
    struct payload *payload; /**< Payload */
    uint8_t seq_send; /**< Seq state for sending */
};

/**
** \brief Allocate and initialize a new message from an init packet.
**
** \param init_packet The initialisation packet of the message.
** \return Success: The new allocated and initialiazed message.
**         Failure: NULL.
*/
struct message *message_new(const struct packet_init *init_packet);

/**
** \brief Allocate and initialize a new blank message.
**
** \param cid The channel id.
** \param cmd The associated command.
** \return Success: The new allocated and initialized blank message.
**         Failure: NULL.
*/
struct message *message_new_blank(uint32_t cid, uint8_t cmd);

/**
** \brief Allocate and initialize a new message from data.
**
** \param cid The channel id.
** \param cmd The associated command.
** \param data The data to put in the message.
** \param size The size of the data.
** \return Success: The new allocated and initialized message.
**         Failure: NULL.
*/
struct message *message_new_from_data(uint32_t cid, uint8_t cmd,
        const uint8_t *data, size_t size);

/**
** \brief Allocate and initialize a new message from payload.
**
** \param cid The channel id.
** \param cmd The associated command.
** \param payload The payload ot put in the message.
** \return Success: The new allocated and initialized message.
**         Failure: NULL.
*/
struct message *message_new_from_payload(uint32_t cid, uint8_t cmd,
        const struct payload *payload);

/**
** \brief Allocate and initialize a new message from another message.
**
** \param message The message to copy.
** \return Success: The new allocated and initialized message.
**         Failure: NULL.
*/
struct message *message_copy(const struct message *message);

/**
** \brief Add data to a message.
**
** \param message The message to add data to.
** \param data The data to add.
** \param size The size of the data.
** \return Success: true.
**         Failure: false.
*/
bool message_add_data(struct message *message,
        const uint8_t *data, size_t size);

/**
** \brief Add a part to a message.
**
** \param message The message.
** \param cont_packet The continuation packet.
** \return Success: true.
**         Failure: false.
*/
bool message_add_part(struct message *message,
        const struct packet_cont *cont_packet);

/**
** \brief Get next packet part of a message for sending a message.
**
** \param message The message to get the next packet from.
** \param packet_ref Packet reference to put the crafted packet.
** \return End of message: false.
**         Not end of message: true.
*/
bool message_next_packet(struct message *message,
        void **packet_ref);

/**
** \brief Free a message.
**
** \param message The message to free.
*/
void message_free(struct message *message);

#endif
