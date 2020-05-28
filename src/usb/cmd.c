#include <stddef.h>

#include "cmd.h"


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