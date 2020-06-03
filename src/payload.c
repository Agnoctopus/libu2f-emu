#include <stdlib.h>
#include <string.h>

#include "payload.h"


/* Floor and ceil util */
#define FLOOR_NB(nb, m) ((nb) & ~((m) - 1))
#define CEIL_NB(nb, m) FLOOR_NB(nb + m - 1, m)


struct payload *payload_new_with_capacity(uint16_t capacity)
{
    /* Allocate */
    struct payload *payload = malloc(sizeof(struct payload));
    if (payload == NULL)
        return NULL;

    /* Attributes */
    payload->size = 0;
    payload->capacity = CEIL_NB(capacity, PAYLOAD_DEF_CAP);

    /* Data buffer allocation */
    uint8_t *data = malloc(payload->capacity);
    if (data == NULL)
    {
        /* Release */
        free(payload);
        return NULL;
    }
    payload->data = data;

    return payload;
}

struct payload *payload_new(void)
{
    /* Delegate */
    return payload_new_with_capacity(PAYLOAD_DEF_CAP);
}


struct payload *payload_new_from_data(const uint8_t *data,
        size_t size)
{
    /* Instantiate the message */
    struct payload *payload = payload_new_with_capacity(size);
    if (payload == NULL)
        return NULL;

    /* Add data */
    if (!payload_add_data(payload, data, size))
    {
        /* Release */
        payload_free(payload);
        return NULL;
    }
    return payload;
}

bool payload_add_data(struct payload *payload,
        const uint8_t *data, size_t size)
{
    /* Check size */
    uint16_t size_new = payload->size + size;

    /* Overflow check */
    if (size >= UINT16_MAX || size_new < payload->size)
        return false;

    /* Check capacity */
    if (size_new > payload->capacity)
    {
        /* Expand */
        uint16_t cap_new = CEIL_NB(size_new, PAYLOAD_DEF_CAP);
        uint8_t *data_new = realloc(payload->data, cap_new);
        if (data_new == NULL)
            return false;

        /* Update */
        memcpy(data_new, data, payload->size);
        payload->capacity = cap_new;
        payload->data = data_new;
    }

    /* Add data */
    memcpy(payload->data + payload->size, data, size);

    /* Update */
    payload->size = size_new;

    return true;
}

void payload_free(struct payload *payload)
{
    /* NULL case */
    if (payload == NULL)
        return;

    free(payload->data);
    free(payload);
}
