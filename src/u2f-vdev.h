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
    /* Transports */
    struct transport_core *transport_core; /**< Transport core */

    /* Core */
    struct crypto_core crypto_core; /**< Crypto core */
    struct u2f_emu_vdev_counter *counter; /**< Global counter */

    /* Other attributes */
    bool is_user_counter; /**< User counter */
};


#endif
