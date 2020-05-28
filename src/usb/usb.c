#include <errno.h>
#include <stdlib.h>

#include "cmd.h"
#include "packet.h"
#include "usb.h"

/**
** \brief The packet init handler.
**
** \param state The usb state.
** \param packet The init packet.
** \return Success: The response.
**         Failure / No response: NULL.
*/
static struct message *packet_init_handle(struct usb_state *state,
        const struct packet_init *packet)
{
    /* Encapsule */
    struct message *request = message_new(packet);

    /* Check integrity */
    if (request->size == request->bcnt)
    {
        /* Reponse */
        struct message *response = NULL; //cmd_process(request);

        /* Free */
        message_free(request);

        return response;
    }
    /* Transaction */
    transaction_start(&state->transaction, request);

    return NULL;
}

/**
** \brief The packet cont handler.
**
** \param state The usb state.
** \param packet The cont packet.
** \return Sucess: The response.
**         Failure / No response: NULL.
*/
static struct message *packet_cont_handle(struct usb_state *state,
        const struct packet_cont *packet)
{
    /* Get the transaction request */
    struct message *request = state->transaction.request;

    /* Add cont packet */
    message_add_part(request, packet);

    /* Check integrity */
    if (request->size == request->bcnt)
    {
        /* Process */
        struct message *response = NULL; //cmd_process(request);

        /* End transaction */
        state->in_transaction = false;

        /* Free */
        message_free(request);

        return response;
    }

    return NULL;
}

void u2f_emu_vdev_usb_process(void *state, const void *packet,
        size_t size)
{
    /* USB state */
    struct usb_state *usb_state = state;

    /* Get the channel id  */
    uint32_t cid = packet_get_cid(packet);

    /* Check packet size */
    if (size != PACKET_SIZE)
    {
        cmd_generate_error(cid, ERROR_INVALID_CMD);
        return;
    }

    /* Gte the packet_type */
    bool is_init_packet = packet_is_init(packet);

    if (is_init_packet)
    {
        if (usb_state->in_transaction)
        {
            cmd_generate_error(cid, ERROR_CHANNEL_BSY);
            return;
        }
        else
        {
            packet_init_handle(usb_state, packet);
            return;
        }
    }
    else
    {
        if (!usb_state->in_transaction)
        {
            cmd_generate_error(cid, ERROR_INVALID_CMD);
            return;
        }

        if (usb_state->transaction.request->cid == cid)
        {
            packet_cont_handle(usb_state, packet);
            return;
        }
        else
        {
            cmd_generate_error(cid, ERROR_CHANNEL_BSY);
            return;
        }

    }
    /* Should not happend */

    return;
}

int u2f_emu_vdev_usb_state_init(void **state_ref)
{
    /* Allocate */
    struct usb_state *state = malloc(sizeof(struct usb_state));
    if (state == NULL)
        return -errno;

    /* Attributes */
    state->in_transaction = false;

    /* Referance */
    *(struct usb_state **)state_ref = state;

    return 0;
}