#include <errno.h>
#include <stdlib.h>

#include "usb.h"


void u2f_emu_vdev_usb_process(const void *packet, size_t size)
{
    (void)packet;
    (void)size;
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