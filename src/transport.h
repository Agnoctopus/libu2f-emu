#ifndef TRANSPORT_H
#define TRANSPORT_H

#include <stdbool.h>
#include <stdint.h>

#include "u2f-emu-types.h"


/**
** \brief Transport core, managing transports.
*/
struct transport_core;

/**
** \brief Transport state init handler.
*/
typedef int (*state_init_t)(u2f_emu_vdev *vdev, void **state);

/**
** \brief Transport state free handler.
*/
typedef void (*state_free_t)(void *state);

/**
** \brief Input data handler.
*/
typedef void (*input_handler_t)(void *state,
        const void *data, size_t size);

/**
** \brief Response precense checker.
*/
typedef bool (*has_response_t)(void *state);

/**
** \brief Response getter.
*/
typedef size_t (*get_response_t)(void *state, uint8_t **data);

/**
** \brief APDU format setter
*/
typedef bool (*set_apdu_t)(void *state, u2f_emu_apdu apdu);

/**
** \brief Transport info representation.
*/
typedef struct transport_info
{
    u2f_emu_transport type; /**< Type */
    state_init_t state_init; /**< State init */
    state_free_t state_free; /**< State free */
    input_handler_t input_handler; /**< Input handler */
    has_response_t has_response; /**< Response precense checker */
    get_response_t get_response; /**< Response getter */
    set_apdu_t set_apdu; /** APDU format setter */
} transport_info_t;

/**
** \brief Transport representation.
*/
struct transport
{
    const transport_info_t *info; /**< Info about the transport */
    void *state;  /**< State */
};

/**
** \brief Create a new transport_core that manage all transports
**
** \param core_ref The reference to the transport core to create.
** \return Success: true.
**         Failure: false.
*/
bool transport_core_new(u2f_emu_vdev *vdev,
        struct transport_core **core_ref);

/**
** \brief Get a transport from a transport core.
**
** \param core The transport core.
** \param type The transport type.
** \return Success: the transport.
**         Failure: NULL.
*/
const struct transport *transport_get(
        const struct transport_core *core,
        u2f_emu_transport type);


/**
** \brief Get the transport info for a specific transport type.
**
** \param type The transport type.
** \return Sucesss: The speccific transport info.
**         Failure: NULL.
*/
const transport_info_t *transport_info_get(u2f_emu_transport type);

#endif
