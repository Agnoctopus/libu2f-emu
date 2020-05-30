#ifndef TRANSPORT_H
#define TRANSPORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "u2f-emu-types.h"

/**
** \brief Transport state init handler for U2F virtual emulated
**        device transport.
*/
typedef int (*state_init_t)(u2f_emu_vdev *vdev, void **state);

/**
** \brief Input handler for U2F virtual emulated device input
**        processing.
*/
typedef void (*input_handler_t)(void *state,
        const void *data, size_t size);

/**
** \brief Response precense checker for U2F virtual emulated device
**        transport.
*/
typedef bool (*has_response)(void *state);

/**
** \brief Response getter for U2F virtual emulated device transport.
*/
typedef size_t (*get_response)(void *state, uint8_t **data);

/**
** \brief Transport representation.
*/
typedef struct transport
{
    u2f_emu_transport type; /**< Type */
    state_init_t state_init; /**< State init function */
    input_handler_t input_handler; /**< Input handler */
    has_response has_response; /**< Response precense checker */
    get_response get_response; /**< Response getter */
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