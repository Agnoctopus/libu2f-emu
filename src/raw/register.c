#include "raw.h"


struct payload *raw_register_handler(
        const void *packet, size_t size)
{
    (void)packet;
    (void)size;
    return NULL;
}