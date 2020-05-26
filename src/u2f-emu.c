#include <stdlib.h>

#include "u2f-emu.h"
#include "usb/usb.h"


/**
** \brief Input handler for U2F virtual emulated device input
**        processing.
*/
typedef void (*input_handler_t)(const void *data, size_t size);

/**
** \brief Input handlers for U2F virtual emulated device input
**        processing, depending of the associated transport.
*/
static const input_handler_t input_handlers[] =
{
    NULL,
    u2f_emu_vdev_usb_process,
    NULL,
    NULL
};

/**
** \brief Number of inputs handlers
*/
static const size_t input_handlers_nb =
        sizeof(input_handlers) / sizeof(input_handlers[0]);

/**
** \brief U2F virtual emulated device
*/
struct u2f_emu_vdev
{
    u2f_emu_transport transport; /**< The underlaying transport */
    u2f_emu_apdu apdu; /**< The apdu format */
};


u2f_emu_rc u2f_emu_vdev_process(u2f_emu_vdev *vdev,
        const void *data, size_t size)
{
    /* Input handler */
    input_handler_t input_handler;

    /* Transport existance */
    if (vdev->transport < 0 || vdev->transport >= input_handlers_nb)
        return U2F_EMU_SUPPORTED_ERROR;

    /* Get the input handler corresponding to the transport */
    input_handler = input_handlers[vdev->transport];

    /* Check for implementation */
    if (input_handlers == NULL)
        return U2F_EMU_SUPPORTED_ERROR;

    /* Process input */
    input_handler(data, size);

    return U2F_EMU_OK;
}

u2f_emu_rc u2f_emu_vdev_set_apdu(u2f_emu_vdev *vdev,
    u2f_emu_apdu apdu)
{
    /* Check permissions */
    if (vdev->transport != U2F_EMU_NFC
        && vdev->transport != U2F_EMU_AGNOSTIC)
        return U2F_EMU_PERMISSION_ERROR;

    /* Set apdu */
    vdev->apdu = apdu;

    return U2F_EMU_OK;
}

void u2f_emu_vdev_free(u2f_emu_vdev *vdev)
{
    /* Release */
    free(vdev);
}

u2f_emu_rc u2f_emu_vdev_new(u2f_emu_vdev **vdev_ref,
        u2f_emu_transport transport)
{
    /* U2F virtual emulated device being instantiated */
    u2f_emu_vdev *vdev;

    /* Check support */
    if (transport != U2F_EMU_USB)
        return U2F_EMU_SUPPORTED_ERROR;

    /* Allocate */
    vdev = malloc(sizeof(u2f_emu_vdev));
    if (vdev == NULL)
        return U2F_EMU_MEMORY_ERROR;

    /* Initialize */
    vdev->transport = transport;
    vdev->apdu = U2F_EMU_EXTENDED;

    /* Reference */
    *vdev_ref = vdev;

    return U2F_EMU_OK;
}
