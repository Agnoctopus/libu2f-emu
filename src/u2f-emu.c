#include <stdlib.h>

#include "transport.h"
#include "u2f-emu.h"
#include "u2f-vdev.h"
#include "usb/usb.h"


u2f_emu_rc u2f_emu_vdev_send(u2f_emu_vdev *vdev,
        u2f_emu_transport transport_type,
        const void *data, size_t size)
{
    /* Get transport */
    const struct transport *transport =
            transport_get(vdev->transport_core, transport_type);
    if (transport == NULL)
        return U2F_EMU_SUPPORTED_ERROR;

    /* Process input */
    transport->info->input_handler(transport->state, data, size);
    return U2F_EMU_OK;
}

bool u2f_emu_vdev_has_response(u2f_emu_vdev *vdev,
        u2f_emu_transport transport_type)
{
    /* Get transport */
    const struct transport *transport =
            transport_get(vdev->transport_core, transport_type);
    if (transport == NULL)
        return U2F_EMU_SUPPORTED_ERROR;

    /* Check response precense */
    return transport->info->has_response(transport->state);
}

size_t u2f_emu_vdev_get_response(u2f_emu_vdev *vdev,
        u2f_emu_transport transport_type, uint8_t **data)
{
    /* Get transport */
    const struct transport *transport =
            transport_get(vdev->transport_core, transport_type);
    if (transport == NULL)
        return U2F_EMU_SUPPORTED_ERROR;

    /* Get response */
    return transport->info->get_response(transport->state, data);
}

void u2f_emu_vdev_free_response(uint8_t *data)
{
    free(data);
}

u2f_emu_rc u2f_emu_vdev_set_apdu(u2f_emu_vdev *vdev,
    u2f_emu_transport transport_type, u2f_emu_apdu apdu)
{
    /* Get transport */
    const struct transport *transport =
            transport_get(vdev->transport_core, transport_type);
    if (transport == NULL)
        return U2F_EMU_SUPPORTED_ERROR;

    /* Check permission */
    if (transport->info->set_apdu == NULL)
        return U2F_EMU_PERMISSION_ERROR;

    /* Set APDU */
    transport->info->set_apdu(transport->state, apdu);
    return U2F_EMU_OK;
}

/**
** \brief Instantiate a new U2F virtual emulated device base,
**        with the transport configuration.
**
** \param vdev_ref The virtual device reference.
** \return Success: U2F_EMU_OK.
**         Failure: - memory allocation: U2F_EMU_MEMORY_ERROR.
**                  - not supported: U2F_EMU_SUPPORTED_ERROR.
*/
static u2f_emu_rc u2f_emu_vdev_base_new(u2f_emu_vdev **vdev_ref)
{
    /* U2F virtual emulated device being instantiated */
    u2f_emu_vdev *vdev;
    *vdev_ref = NULL;

    /* Allocate */
    vdev = malloc(sizeof(u2f_emu_vdev));
    if (vdev == NULL)
        return U2F_EMU_MEMORY_ERROR;

    /* Transport core */
    if (!transport_core_new(vdev, &vdev->transport_core))
    {
        /* Release */
        free(vdev);
        return U2F_EMU_TRANSPORT_ERROR;
    }

    /* Reference */
    *vdev_ref = vdev;

    return U2F_EMU_OK;
}

u2f_emu_rc u2f_emu_vdev_new_from_dir(u2f_emu_vdev **vdev_ref,
        const char *pathname)
{
    /* Base instantation */
    u2f_emu_vdev *vdev = NULL;
    u2f_emu_rc rc = u2f_emu_vdev_base_new(&vdev);
    if (rc != U2F_EMU_OK)
        return rc;

    /* Counter */
    if (!counter_new_from_dir(pathname, &vdev->counter))
    {
        free(vdev);
        return U2F_EMU_MEMORY_ERROR;
    }
    vdev->is_user_counter = false;


    /* Crypto core */
    if (!crypto_new_from_dir(pathname, &vdev->crypto_core))
    {
        counter_free(vdev->counter);
        free(vdev);
        return U2F_EMU_MEMORY_ERROR;
    }

    /* Reference */
    *vdev_ref = vdev;

    return U2F_EMU_OK;
}

u2f_emu_rc u2f_emu_vdev_new_ephemeral(u2f_emu_vdev **vdev_ref)
{
    /* Base instantation */
    u2f_emu_vdev *vdev = NULL;
    u2f_emu_rc rc = u2f_emu_vdev_base_new(&vdev);
    if (rc != U2F_EMU_OK)
        return rc;

    /* Counter */
    if (!counter_new_epthemeral(&vdev->counter))
    {
        free(vdev);
        return U2F_EMU_MEMORY_ERROR;
    }
    vdev->is_user_counter = false;


    /* Crypto core */
    if (!crypto_new_ephemeral(&vdev->crypto_core))
    {
        counter_free(vdev->counter);
        free(vdev);
        return U2F_EMU_MEMORY_ERROR;
    }

    /* Reference */
    *vdev_ref = vdev;

    return U2F_EMU_OK;
}

u2f_emu_rc u2f_emu_vdev_new(u2f_emu_vdev **vdev_ref,
        const struct u2f_emu_vdev_setup *info)
{
    /* Base instantation */
    u2f_emu_vdev *vdev = NULL;
    u2f_emu_rc rc = u2f_emu_vdev_base_new(&vdev);
    if (rc != U2F_EMU_OK)
        return rc;

    /* Counter */
    vdev->counter = info->counter;
    vdev->is_user_counter = true;

    /* Crypto core */
    if (!crypto_new_from_dir(NULL, &vdev->crypto_core))
    {
        free(vdev);
        return U2F_EMU_MEMORY_ERROR;
    }

    /* Reference */
    *vdev_ref = vdev;

    return U2F_EMU_OK;
}

void u2f_emu_vdev_free(u2f_emu_vdev *vdev)
{
    /* NULL case */
    if (vdev == NULL)
        return;

    /* Release */
    transport_core_free(vdev->transport_core);
    crypto_free(vdev->crypto_core);
    if (!vdev->is_user_counter)
        counter_free(vdev->counter);
    free(vdev);
}