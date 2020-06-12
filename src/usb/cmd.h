#ifndef CMD_H
#define CMD_H

#include <stdint.h>

#include "message.h"
#include "usb.h"


/* bit macro */
#define BIT(x) (1 << (x))

/* Packed macro */
#define __packed __attribute__((__packed__))

/* Command bits */
#define CMD_PING    BIT(7) | 0x1
#define CMD_MSG     BIT(7) | 0x3
#define CMD_LOCK    BIT(7) | 0x4
#define CMD_INIT    BIT(7) | 0x6
#define CMD_WINK    BIT(7) | 0x8
#define CMD_SYNC    BIT(7) | 0x3c
#define CMD_ERROR   BIT(7) | 0x3f

/* Errors bits */
#define ERR_NONE            0x00 /**< No error */
#define ERR_INVALID_CMD     0x01 /**< Invalid command */
#define ERR_INVALID_PAR     0x02 /**< Invalid parameter */
#define ERR_INVALID_LEN     0x03 /**< Invalid message length */
#define ERR_INVALID_SEQ     0x04 /**< Invalide message sequencing */
#define ERR_MSG_TIMEOUT     0x05 /**< Message has timed out */
#define ERR_CHANNEL_BUSY    0x06 /**< Channel is busy */
#define ERR_LOCK_REQUIRED   0x0a /**< Command requires channel lock */
#define ERR_SYNC_FAILED     0x0b /**< Command sync failed */
#define ERR_INVALID_CID     0x0b /**< Message on CID 0 */
#define ERR_OTHER           0x7f /**< Other unspecified error */

/* Init CMD informations */
#define U2FHID_INIT_BCNT 8
#define PROTOCOL_VERSION 2
#define MAJ_DEV_VERSION 0
#define MIN_DEV_VERSION 1
#define BUILD_DEV_VERSION 0
#define CAP_FLAGS 0
#define CAPABILITY_WINK 0

/**
** \brief The command init reponse payload
*/
struct cmd_init_resp_payload
{
    uint8_t nonce[8]; /**< Nonce */
    uint32_t cid; /**< Channel id */
    uint8_t protocol_ver; /**< U2FHID protocol version */
    uint8_t maj_dev_ver; /**< Major device version */
    uint8_t min_dev_ver; /**< Minor device version */
    uint8_t build_dev_ver; /**< Build device version */
    uint8_t cap_flags; /**< Capabilities flags */
} __packed;

/**
** \brief Get the command error description.
**
** \param error_nb The error number.
** \return The respective error description
*/
const char *cmd_strerror(int error_nb);

/**
** \brief Generate an error response.
**
** \param cid Channel id.
** \param error The error.
** \return The respective error reponse generated
*/
struct message *cmd_generate_error(uint32_t cid, uint8_t error);

/**
** \brief Process a command request.
**
** \param state The USB transport state.
** \param request The command request message.
** \return The reponse generated bu the request process.
*/
struct message *cmd_process(struct usb_state *state,
        const struct message *request);


#endif
