#ifndef APDU_H
#define APDU_H

#include <stdbool.h>
#include <stdint.h>

#include "payload.h"
#include "transport.h"
#include "u2f-emu.h"


/**
** \brief The APDU transport
*/
extern transport_info_t apdu_transport;

/**
** \brief APDU transport state.
*/
struct apdu_state
{
    /* Upper device link */
    u2f_emu_vdev *vdev;

    /* Messaging */
    struct payload *response; /**< Last response */
    u2f_emu_apdu apdu; /**< APDU format */
};

/**
** \brief Init the APDU state.
**
** \param vdev The virtual device.
** \param state_ref The APDU transport state ref.
** \return Sucess: 0.
**         Failure: -errno.
*/
int u2f_emu_vdev_apdu_state_init(u2f_emu_vdev *vdev,
        void **state_ref);

/**
** \brief Free the APDU state.
**
** \param state The APDU transport state.
*/
void u2f_emu_vdev_apdu_state_free(void *state);

/**
** \brief Process incoming data from an APDU.
**
** \param state The APDU transport state.
** \param apdu The APDU.
** \param size The size of the APDU packet.
*/
void u2f_emu_vdev_apdu_process(void *state,
        const void *apdu, size_t size);

/**
** \brief Check the precense of a response from the APDU transport.
** \param state The APDU transport state.
** \return Has response: true.
**         Has no response: false.
*/
bool u2f_emu_vdev_apdu_has_response(void *state);

/**
** \brief Get the response frim the APDU transport.
**
** \param state The APDU transport state.
** \param data The data ref buffer to put rhe resonse
** \return The size of the allocated data.
*/
size_t u2f_emu_vdev_apdu_get_response(void *state, uint8_t **data);

/**
** \brief Get the response frim the APDU transport.
**
** \param state The APDU transport state.
** \param data The data ref buffer to put rhe resonse
** \return The size of the allocated data.
*/
void u2f_emu_vdev_apdu_set_apdu(void *state, u2f_emu_apdu apdu);

#endif
