#ifndef PACKET_H
#define PACKET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>


/* bit macro */
#define BIT(x) (1 << (x))

/* Packed macro */
#define __packed __attribute__((__packed__))

/* Packet general size */
#define PACKET_SIZE 64

/* Init packet specific sizes */
#define PACKET_INIT_HEADER_SIZE 7
#define PACKET_INIT_DATA_SIZE (PACKET_SIZE - PACKET_INIT_HEADER_SIZE)

/* Cont packet specific sizes */
#define PACKET_CONT_HEADER_SIZE 5
#define PACKET_CONT_DATA_SIZE (PACKET_SIZE - PACKET_CONT_HEADER_SIZE)
#define PACKET_CONT_MAX_SEQ (BIT(7) - 1)

/* Broadcast channels */
#define BROADCAST_CHANNEL 0xFFFFFFFF

/**
** \brief U2FHID packet use for start messsaging during transaction
*/
struct packet_init
{
    uint32_t cid; /**< Channel identifier */
    uint8_t cmd; /**< Command identifier (bit 7 set) */
    uint8_t bcnth; /**< High part of payload length */
    uint8_t bcntl; /**< Low part of the payload length */
    uint8_t data[PACKET_INIT_DATA_SIZE]; /**< Payload data */
};

/**
** \brief U2FHID packet use for start messsaging during transaction
*/
struct packet_cont
{
    uint32_t cid; /**< Channel identifier */
    uint8_t seq; /**< Packet sequence 0x00..0x7f (bit 7 cleared)*/
    uint8_t data[PACKET_CONT_DATA_SIZE]; /**< Payload data */
};

/**
** \brief Get the channel id of a packet
**
** \param packet The packet
** \return The channel id
*/
static inline uint32_t packet_get_cid(const void *packet)
{
    return *((uint32_t *)packet);
}

/**
** \brief Check if a packet is an init packet
**
** \param packet The packet
** \return true : init packet, false: cont packet
*/
static inline bool packet_is_init(const void *packet)
{
    return ((uint8_t *)packet)[4] & (1 << 7);
}

/**
** \brief Get the bcnt of an init packet
**
** \param init_packet The init packet
** \return The bcnt
*/
static inline uint16_t packet_init_get_bcnt(
        const struct packet_init *init_packet)
{
    uint16_t bcnt = 0;
    bcnt |= init_packet->bcnth << 8;
    bcnt |= init_packet->bcntl;

    return bcnt;
}

/**
** \brief Set the bcnt of an init packet
**
** \param init_packet The init packet
** \param bcnt The bcnt to set
*/
static inline void packet_init_set_bcnt(
        struct packet_init *init_packet, uint16_t bcnt)
{
    /* High */
    init_packet->bcnth = bcnt >> 8;

    /* Low */
    init_packet->bcntl = bcnt & 0xFF;
}

/**
** \brief Add a number to the current bcnt of an init packet
**
** \param init_packet The init_packet
** \param value The value to add to bcnt
*/
static inline void packet_init_add_bcnt(
        struct packet_init *init_packet, uint16_t value)
{
    /* Current bcnt */
    uint16_t bcnt = packet_init_get_bcnt(init_packet);

    /* Update */
    packet_init_set_bcnt(init_packet, bcnt + value);
}

/**
** \brief Allocate and initialize a initialisation packet
**
** \param cid The channel id
** \param cmd The commannd
** \param bcnt The payload length
** \return The initialisation packet allocated and initialized
*/
struct packet_init *packet_init_new(uint32_t cid, uint8_t cmd,
        uint16_t bcnt);

/**
** \brief Allocate and initialize a initialisation packet
**
** \param cid The channel id
** \param seq The packet sequence
** \return The continuation packet allocated and initialized
*/
struct packet_cont *packet_cont_new(uint32_t cid, uint8_t seq);

/**
** \brief Copy a packet
**
** \param packet The packet to copy
** \return The copy
*/
void *packet_copy(const void *packet);

#endif
