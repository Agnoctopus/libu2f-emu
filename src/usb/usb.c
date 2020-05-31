#include <errno.h>
#include <stdlib.h>

#include "cmd.h"
#include "packet.h"
#include "time.h"
#include "usb.h"

#include <stdio.h>

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

    /* Generate a new cid */
    if (request->cid == BROADCAST_CID)
        request->cid = rand_r(&state->cid_seed);

    /* Transaction */
    transaction_start(&state->transaction, request);
    state->in_transaction = true;

    /* Check integrity */
    if (request->payload->size == request->bcnt)
    {
        /* Reponse */
        struct message *response = cmd_process(state, request);
        state->transaction.response = response;

        return response;
    }
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
    if (request->payload->size == request->bcnt)
    {
        /* Process */
        struct message *response = cmd_process(state, request);
        state->transaction.response = response;

        return response;
    }

    return NULL;
}

void u2f_emu_vdev_usb_process(void *state,
        const void *packet, size_t size)
{
    /* USB state */
    struct usb_state *usb_state = state;

    /* Get the channel id  */
    uint32_t cid = packet_get_cid(packet);

    /* Check packet size */
    if (size != PACKET_SIZE)
    {
        usb_state->response =
                cmd_generate_error(cid, ERROR_INVALID_CMD);
        return;
    }

    /* Gte the packet_type */
    bool is_init_packet = packet_is_init(packet);
    struct message *response = NULL;

    /* Siwtch packet type */
    if (is_init_packet)
    {
        if (usb_state->in_transaction)
            response = cmd_generate_error(cid, ERROR_CHANNEL_BSY);
        else
            response = packet_init_handle(usb_state, packet);
    }
    else
    {
        if (usb_state->in_transaction
            && usb_state->transaction.request->cid == cid)
                response = packet_cont_handle(usb_state, packet);
        else
            response = cmd_generate_error(cid, ERROR_INVALID_CMD);
    }

    /* Override current response */
    if (response != NULL)
        usb_state->response = response;
}

int u2f_emu_vdev_usb_state_init(u2f_emu_vdev *vdev,
        void **state_ref)
{
    /* Allocate */
    struct usb_state *state = malloc(sizeof(struct usb_state));
    if (state == NULL)
        return -errno;

    /* Attributes */
    state->in_transaction = false;
    state->cid_seed = time(NULL);
    state->vdev = vdev;

    /* Referance */
    *(struct usb_state **)state_ref = state;

    return 0;
}

bool u2f_emu_vdev_usb_has_response(void *state)
{
    /* USB state */
    struct usb_state *usb_state = state;

    return usb_state->response != NULL;
}

size_t u2f_emu_vdev_usb_get_response(void *state, uint8_t **data)
{
    /* USB state */
    struct usb_state *usb_state = state;

    /* Reset ref */
    *data = NULL;

    /* Check response precense */
    if (!u2f_emu_vdev_usb_has_response(state))
        return 0;

    /* Next packet */
    bool end = !message_next_packet(usb_state->response,
            (void *)data);
    if (end)
    {
        if (usb_state->in_transaction
            && usb_state->response
                == usb_state->transaction.response)
        {
            usb_state->in_transaction = false;
            message_free(usb_state->transaction.request);
        }
        message_free(usb_state->response);
        usb_state->response = NULL;
    }
    /* Error */
    if (data == NULL)
        return 0;
    return PACKET_SIZE;
}

transport_t usb_transport =
{
    .type = U2F_EMU_USB,
    .state_init = u2f_emu_vdev_usb_state_init,
    .input_handler = u2f_emu_vdev_usb_process,
    .has_response = u2f_emu_vdev_usb_has_response,
    .get_response = u2f_emu_vdev_usb_get_response
};