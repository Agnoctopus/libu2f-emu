#ifndef RAW_H
#define RAW_H

#include <stddef.h>
#include <stdint.h>

#include "payload.h"
#include "u2f-emu-types.h"


/* Packed macro */
#define __packed __attribute__((__packed__))

/**
** \brief APDU Frame header.
*/
struct frame_header
{
    uint8_t cla;
    uint8_t ins;
    uint8_t p1;
    uint8_t p2;
    uint8_t optional[4];
} __packed;

/* Commands bits */
#define U2F_REGISTER 0x01
#define U2F_AUTHENTICATE 0x02
#define U2F_VERSION 0x03

/* Status code */
#define SW_NO_ERROR 0x9000
#define SW_CONDITIONS_NOT_SATISFIED 0x6985
#define SW_WRONG_DATA 0x6A80
#define SW_WRONG_LENGTH 0x6700
#define SW_CLA_NOT_SUPPORTED 0x6E00
#define SW_INS_NOT_SUPPORTED 0x6D00

/* Authenticate bits */
#define U2F_AUTH_CHECK 0x07
#define U2F_AUTH_ENFORCE 0x03
#define U2F_AUTH_NO_ENFORCE 0x08

/* U2F version */
#define VERSION_STR "U2F_V2"

/**
** \brief Process incoming data from a RAW APDU.
**
** \param packet The RAW APDU packet.
** \param size The size of the RAW APDU packet.
** \param apdu The APDU format.
*/
struct payload * u2f_emu_vdev_raw_process(
        const void *packet, size_t size, u2f_emu_apdu apdu);


/**
** \brief Handle authentification request.
**
** \param request The authentification request message
** \return The response
*/
struct payload *raw_authenticate_handler(
        const void *packet, size_t size);

/**
** \brief Handle registration request.
**
** \param request The registration request message
** \return The response or null if no response
*/
struct payload *raw_register_handler(
        const void *packet, size_t size);

#endif