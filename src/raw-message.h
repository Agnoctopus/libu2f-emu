#ifndef RAW_MESSAGE_H
#define RAW_MESSAGE_H

#include <stdint.h>
#include <stdio.h>

/* Packed macro */
#define __packed __attribute__((__packed__))

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

#define VERSION_STR "U2F_V2"

#define U2F_APDU_HEADER_SIZE 7

/* Authenticate bits */
#define U2F_AUTH_CHECK 0x07
#define U2F_AUTH_ENFORCE 0x03
#define U2F_AUTH_NO_ENFORCE 0x08

/* Params len */
#define U2F_CHA_PARAM_SIZE 32
#define U2F_APP_PARAM_SIZE 32

/**
** \brief Registration parameter
*/
struct registration_params
{
    /** SHA-256 client data */
    uint8_t challenge_param[U2F_CHA_PARAM_SIZE];
    /** SHA-256 App Id */
    uint8_t application_param[U2F_APP_PARAM_SIZE];
};

struct authentification_params
{
    /** SHA-256 client data */
    uint8_t challenge_param[U2F_CHA_PARAM_SIZE];
    /** SHA-256 App Id */
    uint8_t application_param[U2F_APP_PARAM_SIZE];
    uint8_t key_handle_size;
    uint8_t key_handle[];
};

/**
** \brief The raw message handler
**
** \param request The raw message request
** \return The response
*/
struct message *raw_msg_handler(const struct message *request);

#endif
