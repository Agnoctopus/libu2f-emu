#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "counter.h"


bool counter_increment(struct counter *counter)
{
    /* Increment counter */
    ++counter->value;

    /* Any write back */
    if (counter->fd == -1)
        return true;

    /* Write back */
    if (lseek(counter->fd, 0, SEEK_SET) == -1)
        return false;;
    ssize_t rw = write(counter->fd, &counter->value,
        sizeof(counter->value));
    return rw == sizeof(counter->value);
}

bool counter_setup_from_dir(const char *pathname,
        struct counter *counter)
{
    /* Open dir */
    int dirfd = openat(AT_FDCWD, pathname,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0)
        return false;

    /* Open file */
    int fd = openat(dirfd, COUNTER_FILENAME, O_RDWR | O_CLOEXEC);
    close(dirfd);
    if (fd < 0)
        return false;

    /* Read value  */
    uint32_t value = 0;
    ssize_t rr = read(fd, &value, sizeof(value));
    if (rr < 0)
    {
        close(fd);
        return false;
    }

    /* Assign */
    counter->fd = fd;
    counter->value = value;

    return true;
}

void counter_release(struct counter *counter)
{
    close(counter->fd);
    counter->fd = -1;
}