#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "uhid-dev.h"


/**
** \brief Init an UHID event with a type.
**
** \param ev The event to init.
** \param type The event type.
*/
static inline void uhid_init_event_type(
        struct uhid_event *ev, int type)
{
    /* Wipe event */
    memset(ev, 0, sizeof(struct uhid_event));

    /* Set event type */
    ev->type = type;
}

int uhid_dev_recv_event(int fd, struct uhid_event *ev)
{
    /* Wipe event */
    memset(ev, 0, sizeof(struct uhid_event));

    /* Read event */
    ssize_t ret = read(fd, ev, sizeof(struct uhid_event));
    if (ret == 0)
    {
        warnx("Event: Read HUP on uhid-cdev.");
        return -EFAULT;
    }
    else if (ret < 0)
    {
        warn("Event: Cannot read uhid-cdev");
        return -errno;
    }
    else if (ret != sizeof(struct uhid_event))
    {
        warnx("Invalid size read from uhid-dev: "
            "%ld != %lu (expected).",
            ret, sizeof(struct uhid_event));
        return -EFAULT;
    }
    /* Good */

    return 0;
}

/**
** \brief Send an event to an UHID USB device.
**
** \param fd The fd of the UHID USB device.
** \param ev The event to send.
** \return Success: 0.
**         Failure: -errno.
*/
static int uhid_dev_send_event(int fd,
        const struct uhid_event *ev)
{
    /* Send it */
    ssize_t ret = write(fd, ev, sizeof(struct uhid_event));

    /* Check */
    if (ret < 0)
    {
        warn("Send event: Cannot write to uhid");
        return -errno;
    }
    else if (ret != sizeof(struct uhid_event))
    {
        warnx("Send event: Wrong size written to uhid: "
                "%ld != %lu (expected).",
                ret, sizeof(struct uhid_event));
        return -EFAULT;
    }
    /* Good */

    return 0;
}

int uhid_dev_send_input(int fd, const void *data, size_t size)
{
    /* Check size */
    if (size > UHID_DATA_MAX)
        return -ENOMEM;

    /* Input event */
    struct uhid_event ev;
    uhid_init_event_type(&ev, UHID_INPUT2);

    /* Attributes */
    ev.u.input2.size = size;
    memcpy(&ev.u.input2.data, data, size);

    /* Send event */
    int ret = uhid_dev_send_event(fd, &ev);
    if (ret < 0)
    {
        close(fd);
        return ret;
    }
    return 0;
}

int uhid_dev_destroy(int fd)
{
    /* Destroy event */
    struct uhid_event ev;
    uhid_init_event_type(&ev, UHID_DESTROY);

    /* Send event */
    int ret = uhid_dev_send_event(fd, &ev);

    /* Close the device */
    close(fd);

    return ret;
}

/**
** \brief Open the UHID char device file.
**        By opening this device, we create the USB UHID device
**        which is unitialized.
**
**
** \param uhid_path The UHID char device path.
** \return Sucess: The file descriptor.
**         Failure: -errno.
*/
static inline int uhid_dev_open(const char *uhid_path)
{
    /* Open it */
    int fd = open(uhid_path, O_RDWR | O_CLOEXEC);

    /* Check */
    if (fd < 0)
    {
        warn("UHID open: Cannot open uhid-cdev %s", uhid_path);
        return -errno;
    }
    /* Good */

    return fd;
}

int uhid_dev_new_with_path(const char *uhid_path,
        const struct uhid_create2_req *dev_info)
{
    /* Open UHID char device */
    int fd = uhid_dev_open(uhid_path);
    if (fd < 0)
        return fd;

    /* Create event */
    struct uhid_event ev;
    uhid_init_event_type(&ev, UHID_CREATE2);

    /* Attributes */
    memcpy(&ev.u.create2, dev_info,
        sizeof(struct uhid_create2_req));

    /* Send event */
    int ret = uhid_dev_send_event(fd, &ev);
    if (ret < 0)
    {
        close(fd);
        return ret;
    }
    return fd;
}

int uhid_dev_new(const struct uhid_create2_req *dev_info)
{
    /* Delegate */
    return uhid_dev_new_with_path("/dev/uhid", dev_info);
}
