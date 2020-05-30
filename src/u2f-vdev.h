#ifndef U2F_VDEV_H
#define U2F_VDEV_H

#include "crypto.h"
#include "u2f-emu-types.h"


/**
** \brief U2F virtual emulated device
*/
struct u2f_emu_vdev
{
    /* Transport */
    u2f_emu_transport transport; /**< The underlaying transport */
    u2f_emu_apdu apdu; /**< The apdu format */
    void *transport_state; /**< The transport state */

    /* Crypto core */
    struct crypto_core cyrpto_core;
};


#endif