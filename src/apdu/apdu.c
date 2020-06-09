#include <errno.h>
#include <stdlib.h>

#include "apdu.h"
#include "raw/raw.h"


void u2f_emu_vdev_apdu_set_apdu(void *state, u2f_emu_apdu apdu)
{
    /* USB state */
    struct apdu_state *apdu_state = state;

    apdu_state->apdu = apdu;
}

bool u2f_emu_vdev_apdu_has_response(void *state)
{
    /* USB state */
    struct apdu_state *apdu_state = state;

    return apdu_state->response != NULL;
}

size_t u2f_emu_vdev_apdu_get_response(void *state, uint8_t **data)
{
    /* USB state */
    struct apdu_state *apdu_state = state;

    /* Reset ref */
    *data = NULL;

    /* Check response precense */
    if (!u2f_emu_vdev_apdu_has_response(state))
        return 0;

    /* Get from response payload */
    size_t size = apdu_state->response->size;
    *data = apdu_state->response->data;
    free(apdu_state->response);

    return size;
}

void u2f_emu_vdev_apdu_process(void *state,
        const void *packet, size_t size)
{
    /* USB state */
    struct apdu_state *apdu_state = state;

    /* Raw process */
    struct payload *response =
            u2f_emu_vdev_raw_process(apdu_state->vdev, packet, size);

    /* Reference */
    if (response != NULL)
    {
        payload_free(apdu_state->response);
        apdu_state->response = response;
    }
}

void u2f_emu_vdev_apdu_state_free(void *state)
{
    /* USB state */
    struct apdu_state *apdu_state = state;

    /* NULL case */
    if (apdu_state == NULL)
        return;

    /* Waiting response */
    if (apdu_state->response != NULL)
        payload_free(apdu_state->response);

    /* Release */
    free(apdu_state);
}

int u2f_emu_vdev_apdu_state_init(u2f_emu_vdev *vdev,
        void **state_ref)
{
    /* Allocate */
    struct apdu_state *state = malloc(sizeof(struct apdu_state));
    if (state == NULL)
        return -errno;

    /* Attributes */
    state->vdev = vdev;
    state->response = NULL;
    state->apdu = U2F_EMU_SHORT;

    /* Referance */
    *(struct apdu_state **)state_ref = state;

    return 0;
}

transport_info_t apdu_transport =
{
    .type = U2F_EMU_USB,
    .state_init = u2f_emu_vdev_apdu_state_init,
    .state_free = u2f_emu_vdev_apdu_state_free,
    .input_handler = u2f_emu_vdev_apdu_process,
    .has_response = u2f_emu_vdev_apdu_has_response,
    .get_response = u2f_emu_vdev_apdu_get_response,
    .set_apdu = u2f_emu_vdev_apdu_set_apdu
};
