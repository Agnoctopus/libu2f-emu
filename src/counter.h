#ifndef COUNTER_H
#define COUNTER_H

#include <stdbool.h>
#include <stdint.h>


#define COUNTER_FILENAME "counter"

/**
** \brief Counter representation.
*/
struct counter
{
    int fd; /**< Counter fd for write back operation */
    uint32_t value; /**< Value of the counter */
};

/**
** \brief Increment the counter of an U2F virtual device.
**
** \param counter The counter to increment.
** \return Sucessful: true.
**         Failure on write back: false.
*/
bool counter_increment(struct counter *counter);


/**
** \brief Init the counter of an U2F virtual device.
**
** \param pathname The pathname of the setup_dir.
** \param counter The counter to init.
** \return Success: true.
**         Failure: false.
*/
bool counter_setup_from_dir(const char *pathname,
        struct counter *counter);

/**
** \brief Release the ressources used by the counter.
**
** \param counter The counter to release.
*/
void counter_release(struct counter *counter);

#endif