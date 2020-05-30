#ifndef USB_H
#define USB_H

#include <stdbool.h>
#include <stdint.h>

#include "message.h"
#include "transaction.h"
#include "transport.h"
#include "u2f-emu.h"

/**
** \brief The USB transport
*/
extern transport_t usb_transport;

/**
** \brief USB transport state.
*/
struct usb_state
{
    /* Internal */
    uint32_t cid_seed; /**< Seed used to generate random cid */

    /* Messaging */
    struct transaction transaction; /**< Current transaction */
    bool in_transaction; /**< Are we in a transaction */
    struct message *response; /**< Last response */

};

/**
** \brief Init the USB state.
**
** \param state_ref The USB transport state ref.
** \return Sucess: 0.
**         Failure: -errno.
*/
int u2f_emu_vdev_usb_state_init(void **state_ref);

/**
** \brief Process incoming data from an USB HID packet.
**
** \param state The USB transport state.
** \param packet The USB HID packet.
** \param size The size of the USB HID packet.
*/
void u2f_emu_vdev_usb_process(void *state,
        const void *packet, size_t size);

/**
** \brief Check the precense of a response from the USB transport.
** \param state The USB transport state.
** \return Has response: true.
**         Has no response: false.
*/
bool u2f_emu_vdev_usb_has_response(void *state);

/**
** \brief Get the response frim the USB transport.
**
** \param state The USB transport state.
** \param data The data ref buffer to put rhe resonse
** \return The size of the allocated data.
*/
size_t u2f_emu_vdev_usb_get_response(void *state, uint8_t **data);

#endif