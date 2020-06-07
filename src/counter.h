#ifndef COUNTER_H
#define COUNTER_H

#include <stdbool.h>
#include <stdint.h>

#include "u2f-emu-types.h"


#define COUNTER_FILENAME "counter"

/**
** \brief Create a new counter that sync with the counter file
**        inside the setup directory.
**
** \param pathname The pathname of the setup directory.
** \param counter_ref The reference to the counter to create.
** \return Success: true.
**         Failure: false.
*/
bool counter_new_from_dir(const char *pathname,
        struct u2f_emu_vdev_counter **counter_ref);

/**
** \brief Release the ressources used by the counter.
**
** \param vdev_counter The virtual device counter to release.
*/
void counter_release(struct u2f_emu_vdev_counter *vdev_counter);

#endif
