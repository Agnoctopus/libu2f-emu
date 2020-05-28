#ifndef CMD_H
#define CMD_H

#include <stdint.h>

#include "message.h"


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
#define ERROR_INVALID_CMD   1
#define ERROR_INVALID_PAR   2
#define ERROR_INVALID_LEN   3
#define ERROR_INVALID_SEQ   4
#define ERROR_MSG_TIMEOUT   5
#define ERROR_CHANNEL_BSY   6
#define ERROR_CMD_LOCK_RQ   7
#define ERROR_SYNC_FAILED   8


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

#endif