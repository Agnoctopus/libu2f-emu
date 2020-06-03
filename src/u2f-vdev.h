#ifndef U2F_VDEV_H
#define U2F_VDEV_H

#include "counter.h"
#include "crypto.h"
#include "transport.h"
#include "u2f-emu-types.h"


/**
** \brief U2F virtual emulated device
*/
struct u2f_emu_vdev
{
    /* Transport */
    const transport_t *transport; /**< Underlaying transport */
    void *transport_state; /**< Transport state */
    u2f_emu_apdu apdu; /**< Apdu format */

    /* Crypto core */
    struct crypto_core crypto_core; /**< Crypto core */

    /* Global attributes */
    struct counter counter;
};


#endif