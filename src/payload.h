#ifndef PAYLOAD_H
#define PAYLOAD_H

#include <stdbool.h>
#include <stdint.h>


/**
** \brief Payload default capacity.
*/
#define PAYLOAD_DEF_CAP 1024

/**
** \brief Payload represenation.
*/
struct payload
{
    uint16_t size; /**< Size of the payload */
    uint8_t *data;  /**< The contained data of the payload */
    uint16_t capacity; /**< The capacity of the payload */
};


/**
** \brief Allocate and initialize a new payload with a capacity.
**
** \param capacity The capacity of the payload.
** \return Success: The new allocated and initialiazed payload.
**         Failure: NULL.
*/
struct payload *payload_new_with_capacity(uint16_t capacity);

/**
** \brief Allocate and initialize a new payload with a default
**        capacity.
**
** \return Success: The new allocated and initialiazed payload.
**         Failure: NULL.
*/
struct payload *payload_new(void);


/**
** \brief Allocate and initialize a new payload from data.
**
** \param data The data to put in the payload.
** \param size The size of the data.
** \return Success: The new allocated and initialized payload.
**         Failure: NULL.
*/
struct payload *payload_new_from_data(const uint8_t *data,
        size_t size);


/**
** \brief Add data to a payload.
**
** \param message The payload to add data to.
** \param data The data to add.
** \param size The size of the data.
** \return Success: true.
**         Failure: false.
*/
bool payload_add_data(struct payload *payload,
        const uint8_t *data, size_t size);

/**
** \brief Free a payload.
**
** \param message The payload to free.
*/
void payload_free(struct payload *payload);

#endif