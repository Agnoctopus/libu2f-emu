#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "counter.h"


/**
** \brief Counter representation which can sync with the counter
**        file of the setup dir.
*/
struct counter
{
    /* Virtual device counter */
    struct u2f_emu_vdev_counter vdev_counter;

    /* Private attributes */
    uint32_t value; /**< Value of the counter */

    /* Synchronisation */
    int fd; /**< File fd for write back operation */
    bool is_synced; /**< Is the counter synced with a file */
};

/**
** \brief Increment the counter of an U2F virtual device.
**
** \param vdev_counter The virtual device counter to increment.
*/
static void counter_increment(
        struct u2f_emu_vdev_counter *vdev_counter)
{
    /* Get counter */
    struct counter *counter = (struct counter *)vdev_counter;

    /* Increment counter */
    ++counter->value;

    /* Synced Check */
    if (!counter->is_synced)
        return;

    /* Write back */
    if (lseek(counter->fd, 0, SEEK_SET) == -1)
        return;
    write(counter->fd, &counter->value, sizeof(counter->value));
}

/**
** \brief Read the counter value of an U2F virtual device.
**
** \param vdev_counter The virtual device counter to read.
** \return The counter value.
*/
static uint32_t counter_read(
        struct u2f_emu_vdev_counter *vdev_counter)
{
    /* Get counter */
    struct counter *counter = (struct counter *)vdev_counter;
    return counter->value;
}

/**
** \brief Open the counter file from the setup dir.
**
** \param pathname The pathname of the setup dir.
** \return Success: The fd.
**         Failure: -1.
*/
static int counter_open_file(const char *pathname)
{
    /* Open dir */
    int dirfd = openat(AT_FDCWD, pathname,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0)
        return dirfd;

    /* Open file */
    int fd = openat(dirfd, COUNTER_FILENAME, O_RDWR | O_CLOEXEC);
    close(dirfd);
    return fd;
}

bool counter_new_from_dir(const char *pathname,
        struct u2f_emu_vdev_counter **vdev_counter_ref)
{
    /* Instantiate */
    struct counter *counter = malloc(sizeof(struct counter));
    if (counter == NULL)
        return false;

    /* Retrieve value */
    int fd = counter_open_file(pathname);
    if (fd < 0)
    {
        free(counter);
        return false;
    }

    /* Read value  */
    uint32_t value = 0;
    ssize_t rr = read(fd, &value, sizeof(value));
    if (rr < 0)
    {
        close(fd);
        return false;
    }

    /* Initialize */
    counter->vdev_counter.counter_increment = counter_increment;
    counter->vdev_counter.counter_read = counter_read;
    counter->value = value;
    counter->fd = fd;
    counter->is_synced = true;

    /* Reference */
    *vdev_counter_ref = (struct u2f_emu_vdev_counter *)counter;

    return true;
}


bool counter_new_epthemeral(
        struct u2f_emu_vdev_counter **vdev_counter_ref)
{
    /* Instantiate */
    struct counter *counter =
            malloc(sizeof(struct counter));
    if (counter == NULL)
        return false;


    /* Initialize */
    counter->vdev_counter.counter_increment = counter_increment;
    counter->vdev_counter.counter_read = counter_read;
    counter->value = 0;
    counter->is_synced = false;

    /* Reference */
    *vdev_counter_ref = (struct u2f_emu_vdev_counter *)counter;

    return true;
}

void counter_free(struct u2f_emu_vdev_counter *vdev_counter)
{
    /* Get counter */
    struct counter *counter = (struct counter*)vdev_counter;

    /* Release */
    free(counter);
}
