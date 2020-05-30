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
** \brief Process incoming data from an USB HID packet.
**
** \param state The transport state.
** \param packet The USB HID packet.
** \param size The size of the USB HID packet.
*/
void u2f_emu_vdev_usb_process(void *state,
        const void *packet, size_t size);

/**
** \brief Init the USB state.
**
** \param state_ref The USB state ref.
** \return Sucess: 0.
**         Failure: -errno.
*/
int u2f_emu_vdev_usb_state_init(void **state_ref);

#endif