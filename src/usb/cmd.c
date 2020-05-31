#include <stddef.h>
#include <string.h>

#include "cmd.h"
#include "raw/raw.h"


/**
** \brief Commands handler for U2FHID commands processing.
*/
typedef
struct message *(*cmd_handler_t)(struct usb_state *state,
        const struct message *request);

/* All commands handler declaration */
static struct message *cmd_ping_handler(
        struct usb_state *state,
        const struct message *request);
static struct message *cmd_msg_handler(
        struct usb_state *state,
        const struct message *request);
static struct message *cmd_lock_handler(
        struct usb_state *state,
        const struct message *request);
static struct message *cmd_init_handler(
        struct usb_state *state,
        const struct message *request);
static struct message *cmd_wink_handler(
        struct usb_state *state,
        const struct message *request);
static struct message *cmd_sync_handler(
        struct usb_state *state,
        const struct message *request);
static struct message *cmd_error_handler(
        struct usb_state *state,
        const struct message *request);

/**
** \brief Command of U2FHID.
*/
typedef struct cmd
{
    uint8_t cmd; /**< The command number */
    cmd_handler_t handler; /**< The command handler */
} cmd_t;

/**
** \brief Commands handlers for U2FHID commands processing, depending
**        of the associated command.
*/
static const cmd_t cmds[] =
{
    { CMD_PING,  cmd_ping_handler  },
    { CMD_MSG,   cmd_msg_handler   },
    { CMD_LOCK,  cmd_lock_handler  },
    { CMD_INIT,  cmd_init_handler  },
    { CMD_WINK,  cmd_wink_handler  },
    { CMD_SYNC,  cmd_sync_handler  },
    { CMD_ERROR, cmd_error_handler }
};


/**
** \brief Number of commands.
*/
static const size_t cmds_nb = sizeof(cmds) / sizeof(cmds[0]);


/**
** \brief Get the command handler for a specific command.
**
** \param cmd The command.
** \return The command handler?
*/
static cmd_handler_t cmd_get_handler(uint8_t cmd)
{
    /* Loop though commands entries */
    for (size_t i = 0; i < cmds_nb; ++i)
    {
        if (cmd == cmds[i].cmd)
            return cmds[i].handler;
    }
    return NULL;
}

const char *cmd_strerror(int error_nb)
{
    /* Error switch */
    switch (error_nb)
    {
        case ERROR_INVALID_CMD:
            return "Invalid command";
        case ERROR_INVALID_PAR:
            return "Invalid parameter";
        case ERROR_INVALID_LEN:
            return "Invalid message length";
        case ERROR_INVALID_SEQ:
            return "Invalid message sequence";
        case ERROR_MSG_TIMEOUT:
            return "Invalid timed out";
        case ERROR_CHANNEL_BSY:
            return "Channel busy";
        case ERROR_CMD_LOCK_RQ:
            return "Command require channel lock";
        case ERROR_SYNC_FAILED:
            return "Command sync failed";
        default:
            return "Unknow command";
    }
    /* Should never be executed */

    return NULL;
}

struct message *cmd_generate_error(uint32_t cid, uint8_t error)
{
    /* Construct the response error  */
    struct message *response = message_new_blank(cid, CMD_ERROR);
    message_add_data(response, &error, sizeof(uint8_t));

    return response;
}

/**
** \brief The Handler for CMD_PING.
**
** \param state The USB transport state.
** \param request The request.
** \return The response.
*/
static struct message *cmd_ping_handler(
        struct usb_state *state,
        const struct message *request)
{
    (void) request;
    return NULL;
}

/**
** \brief The Handler for CMD_MSG.
**
** \param state The USB transport state.
** \param request The request.
** \return The response.
*/
static struct message *cmd_msg_handler(
        struct usb_state *state,
        const struct message *request)
{
    /* Process Data */
    struct payload *payload = u2f_emu_vdev_raw_process(
            state->vdev,
            request->payload->data,
            request->payload->size);

    /* Encapsulate in a message */
    struct message *response = message_new_from_data(request->cid,
            request->cmd, payload->data, payload->size);

    /* Release */
    payload_free(payload);

    return response;
}

/**
** \brief The Handler for CMD_LOCK.
**
** \param state The USB transport state.
** \param request The request.
** \return The response.
*/
static struct message *cmd_lock_handler(
        struct usb_state *state,
        const struct message *request)
{
    (void) request;
    return NULL;
}

/**
** \brief The Handler for CMD_WINK.
**
** \param state The USB transport state.
** \param request The request.
** \return The response.
*/
static struct message *cmd_wink_handler(
        struct usb_state *state,
        const struct message *request)
{
    (void) request;
    return NULL;
}

/**
** \brief The Handler for CMD_INIT.
**
** \param state The USB transport state.
** \param request The request
** \return The response.
*/
static struct message *cmd_init_handler(
        struct usb_state *state,
        const struct message *request)
{
    /* Check message size*/
    if (request->bcnt != U2FHID_INIT_BCNT)
        return NULL;

    /* Create response */
    struct message *response =
            message_new_blank(BROADCAST_CID, CMD_INIT);

    /* Construct the response payload */
    struct cmd_init_resp_payload payload;

    /* Fill payload */
    memcpy(&payload.nonce, request->payload->data,
            sizeof(payload.nonce));
    payload.cid = request->cid;
    payload.protocol_ver = PROTOCOL_VERSION;
    payload.maj_dev_ver = MAJ_DEV_VERSION;
    payload.min_dev_ver = MIN_DEV_VERSION;
    payload.build_dev_ver = BUILD_DEV_VERSION;
    payload.cap_flags = CAP_FLAGS;

    /* Add payoad to the message */
    message_add_data(response, (uint8_t *)&payload,
            sizeof(struct cmd_init_resp_payload));

    return response;
}

/**
** \brief The Handler for CMD_SYNC.
**
** \param state The USB transport state.
** \param request The request.
** \return The response.
*/
static struct message *cmd_sync_handler(
        struct usb_state *state,
        const struct message *request)
{
    (void) request;
    return NULL;
}

/**
** \brief The Handler for CMD_ERROR.
**
** \param state The USB transport state.
** \param request The request.
** \return The response.
*/
static struct message *cmd_error_handler(
        struct usb_state *state,
        const struct message *request)
{
    (void) request;
    return NULL;
}

struct message *cmd_process(struct usb_state *state,
        const struct message *request)
{
    /* Get the handler */
    cmd_handler_t handler = cmd_get_handler(request->cmd);

    /* Check */
    if (handler == NULL)
        return cmd_generate_error(request->cid,
                ERROR_INVALID_CMD);

    /* Process it */
    return handler(state, request);
}