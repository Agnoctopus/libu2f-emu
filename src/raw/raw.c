#include <string.h>

#include "raw.h"


/**
** \brief Raw cmd handler for U2F APDU processing.
*/
typedef
struct payload *(*raw_cmd_handler_t)(const void *packet, size_t size);

/**
** \brief Raw command of U2F APDU.
*/
typedef struct raw_cmd
{
    uint8_t raw_cmd; /**< The raw command number */
    raw_cmd_handler_t handler; /**< The raw command handler */
} raw_cmd_t;

/* Forward declaration of raw command versio handler */
static struct payload *raw_version_handler(
    const void *packet, size_t size);

/**
** \brief Raw commands handlers for U2F APDU commands processing,
**        depending of the associated command.
*/
static const raw_cmd_t raw_cmds[] =
{
    { U2F_REGISTER,       raw_register_handler     },
    { U2F_AUTHENTICATE,   raw_authenticate_handler },
    { U2F_VERSION,        raw_version_handler      },
};


/**
** \brief Number of commands.
*/
static const size_t raw_cmds_nb =
        sizeof(raw_cmds) / sizeof(raw_cmds[0]);


/**
** \brief Get the raw command handler for a specific raw command.
**
** \param cmd The raw command.
** \return The raw command handler.
*/
static raw_cmd_handler_t raw_cmd_get_handler(uint8_t cmd)
{
    /* Loop though raw command entries */
    for (size_t i = 0; i < raw_cmds_nb; ++i)
    {
        if (cmd == raw_cmds[i].raw_cmd)
            return raw_cmds[i].handler;
    }
    return NULL;
}

/**
** \brief The Handler for U2F_VERSION
**
** \param request The request
** \return The response
*/
static struct payload *raw_version_handler(
    const void *packet, size_t size)
{
    /* Payload */
    struct payload *payload = payload_new();

    /* Version string */
    payload_add_data(payload,
        (uint8_t *)VERSION_STR, strlen(VERSION_STR));

    /* Status code */
    uint8_t status_h = SW_NO_ERROR >> 8;
    uint8_t status_l = SW_NO_ERROR & 0xFF;
    payload_add_data(payload, &status_h, sizeof(uint8_t));
    payload_add_data(payload, &status_l, sizeof(uint8_t));

    return payload;
}


struct payload * u2f_emu_vdev_raw_process(
        const void *packet, size_t size, u2f_emu_apdu apdu)
{
    (void)apdu;

    /* Get frame header */
    struct frame_header *header = (struct frame_header *)packet;

    /* Get raw handler */
    raw_cmd_handler_t handler = raw_cmd_get_handler(header->ins);
    if (handler == NULL)
        return NULL;

    return handler(packet, size);
}