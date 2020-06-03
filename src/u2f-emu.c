#include <stdlib.h>

#include "transport.h"
#include "u2f-emu.h"
#include "u2f-vdev.h"
#include "usb/usb.h"


u2f_emu_rc u2f_emu_vdev_process(u2f_emu_vdev *vdev,
        const void *data, size_t size)
{
    /* Process input */
    vdev->transport->input_handler(vdev->transport_state, data,
            size);
    return U2F_EMU_OK;
}

bool u2f_emu_vdev_has_response(u2f_emu_vdev *vdev)
{
    /* Check response precense */
    return vdev->transport->has_response(vdev->transport_state);
}

size_t u2f_emu_vdev_get_response(u2f_emu_vdev *vdev, uint8_t **data)
{
    /* Get response */
    return vdev->transport->get_response(vdev->transport_state,
            data);
}

u2f_emu_rc u2f_emu_vdev_set_apdu(u2f_emu_vdev *vdev,
    u2f_emu_apdu apdu)
{
    /* Check permissions */
    if (vdev->transport->type != U2F_EMU_NFC
        && vdev->transport->type != U2F_EMU_AGNOSTIC)
        return U2F_EMU_PERMISSION_ERROR;

    /* Set apdu */
    vdev->apdu = apdu;

    return U2F_EMU_OK;
}

void u2f_emu_vdev_free(u2f_emu_vdev *vdev)
{
    /* NULL case */
    if (vdev == NULL)
        return;

    /* Release */
    vdev->transport->state_free(vdev->transport_state);
    crypto_release(&vdev->crypto_core);
    free(vdev);
}

/**
** \brief Init the transport state of an U2F virtual device.
**
** \param vdev The virtual device.
**
** \return Success: U2F_EMU_OK.
**         Failure: - transport does not exist, or is not
**                    implemented: U2F_EMU_SUPPORTED_ERROR:.
**                  - failed to init the transport
**                    state: U2F_EMU_TRANSPORT_ERROR.
*/
static u2f_emu_rc u2f_emu_vdev_transport_state_init(
        u2f_emu_vdev *vdev)
{
    /* Init the transport state */
    int ret = vdev->transport->state_init(vdev,
            &vdev->transport_state);
    if (ret < 0)
        return U2F_EMU_TRANSPORT_ERROR;
    return U2F_EMU_OK;
}

u2f_emu_rc u2f_emu_vdev_new(u2f_emu_vdev **vdev_ref,
        u2f_emu_transport transport_type, const char *setup_dir)
{
    /* U2F virtual emulated device being instantiated */
    u2f_emu_vdev *vdev;
    *vdev_ref = NULL;

    /* Get the transport */
    const transport_t *transport = transport_get(transport_type);
    if (transport == NULL)
        return U2F_EMU_SUPPORTED_ERROR;

    /* Allocate */
    vdev = malloc(sizeof(u2f_emu_vdev));
    if (vdev == NULL)
        return U2F_EMU_MEMORY_ERROR;

    /* Initialize */
    vdev->transport = transport;
    vdev->apdu = U2F_EMU_EXTENDED;

    /* Counter */
    if (!counter_setup_from_dir(setup_dir, &vdev->counter))
    {
        free(vdev);
        return U2F_EMU_MEMORY_ERROR;
    }

    /* Crypto core */
    if (!crypto_setup_from_dir(setup_dir, &vdev->crypto_core))
    {
        counter_release(&vdev->counter);
        free(vdev);
        return U2F_EMU_MEMORY_ERROR;
    }

    /* Transport state */
    u2f_emu_rc rc =
        u2f_emu_vdev_transport_state_init(vdev);
    if (rc != U2F_EMU_OK)
    {
        /* Release */
        counter_release(&vdev->counter);
        crypto_release(&vdev->crypto_core);
        free(vdev);
        return rc;
    }

    /* Reference */
    *vdev_ref = vdev;

    return U2F_EMU_OK;
}
