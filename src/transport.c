#include "transport.h"
#include "usb/usb.h"

/**
** \brief Transports availables for U2F.
*/
static const transport_t *transports[] =
{
    &usb_transport
};

/**
** \brief Number of transports availables for U2F.
*/
static const size_t transports_nb =
    sizeof(transports) / sizeof(transports[0]);


const transport_t *transport_get(u2f_emu_transport type)
{
    /* Loop through transport entries */
    for (size_t i = 0; i < transports_nb; ++i)
    {
        if (type == transports[i]->type)
            return transports[i];
    }
    return NULL;
}
