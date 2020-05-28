#ifndef USB_H
#define USB_H

#include <stdbool.h>

#include "transaction.h"
#include "u2f-emu.h"


/**
** \brief USB transport state.
*/
struct usb_state
{
    struct transaction transaction; /**< Current transaction */
    bool in_transaction; /**< Are we in a transaction */
};

/**
** \brief Process incoming data from an USB HID packet.
**
** \param packet The USB HID packet.
** \param size The size of the USB HID packet.
*/
void u2f_emu_vdev_usb_process(void *state, const void *packet,
        size_t size);

/**
** \brief Init the USB state.
**
** \param state_ref The USB state ref.
** \return Sucess: 0.
**         Failure: -errno.
*/
int u2f_emu_vdev_usb_state_init(void **state_ref);

#endif