#include <stdlib.h>

#include "transport.h"
#include "usb/usb.h"


/**
** \brief Transports availables for U2F.
*/
static const transport_info_t *transports_info[] =
{
    &usb_transport
};

/**
** \brief Number of transports availables for U2F.
*/
static const size_t transports_info_nb =
    sizeof(transports_info) / sizeof(transports_info[0]);

/**
** \brief Transport core.
*/
struct transport_core
{
    /* Transports array */
    struct transport *transports;
};

const transport_info_t *transport_info_get(u2f_emu_transport type)
{
    /* Loop through transport entries */
    for (size_t i = 0; i < transports_info_nb; ++i)
    {
        if (type == transports_info[i]->type)
            return transports_info[i];
    }
    return NULL;
}

const struct transport *transport_get(
        const struct transport_core *core,
        u2f_emu_transport type)
{
    /* Loop through transports info */
    for (size_t i = 0; i < transports_info_nb; ++i)
    {
        if (type == core->transports[i].info->type)
            return &core->transports[i];
    }
    return NULL;
}

void transport_core_free(struct transport_core *core)
{
    /* Loop through transports info */
    for (size_t i = 0; i < transports_info_nb; ++i)
    {
        /* Get transpotr */
        struct transport *transport = &core->transports[i];

        /* Free it */
        transport->info->state_free(transport->state);
    }
    free(core->transports);
    free(core);
}


bool transport_core_new(u2f_emu_vdev *vdev,
        struct transport_core **core_ref)
{
    /* Allocate core */
    struct transport_core *core;
    core = malloc(sizeof(struct transport_core));
    if (core == NULL)
        return false;

    /* Allocate transports */
    struct transport *transports = malloc(sizeof(struct transport));
    if (transports == NULL)
    {
        free(core);
        return transports;
    }

    /* Loop through transports info */
    for (size_t i = 0; i < transports_info_nb; ++i)
    {
        /* Get transport and transport info */
        struct transport *transport = &transports[i];
        const transport_info_t *transport_info = transports_info[i];

        /* Initialize */
        transport->info = transport_info;
        int ret = transport_info->state_init(vdev,
                &transport->state);
        if (ret != 0)
        {
            /* Release all initialized transports */
            for (size_t j = 0; j < i; ++j)
                transport_info->state_free(&transports[i]);
            free(transports);
            free(core);
            return false;
        }
    }
    /* Reference */
    core->transports = transports;
    *core_ref = core;

    return true;
}