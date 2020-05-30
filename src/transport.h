#ifndef TRANSPORT_H
#define TRANSPORT_H

#include <stddef.h>

#include "u2f-emu-types.h"

/**
** \brief Input handler for U2F virtual emulated device input
**        processing.
*/
typedef void (*input_handler_t)(void *state,
        const void *data, size_t size);

/**
** \brief Transport state init handler for U2F virtual emulated
**        device transport.
*/
typedef int (*state_init_t)(void **state);

/**
** \brief Transport representation.
*/
typedef struct transport
{
    u2f_emu_transport type; /**< Type */
    state_init_t state_init; /**< State init function */
    input_handler_t input_handler; /**< Input handler */
} transport_t;


/**
** \brief Get the transport for a specific transport type.
**
** \param type The transport type.
** \return Sucesss: The speccific transport.
**         Failure: NULL.
*/
const transport_t *transport_get(u2f_emu_transport type);

#endif