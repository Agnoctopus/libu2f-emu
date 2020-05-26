#ifndef UHID_DEV_H
#define UHID_DEV_H

#include <linux/uhid.h>
#include <stddef.h>


/**
** \brief Receive an UHID event from the kernel to
**        the UHID USB device.
**
** \param fd The fd of the UHID USB device.
** \param ev The event to fill with the received on.
** \return Sucess: 0.
**         Failure: -errno.
*/
int uhid_dev_recv_event(int fd, struct uhid_event *ev);

/**
** \brief Send input data from the UHID USB device to the kernel.
**
** \param fd The fd of the UHID USB device.
** \param data The data to send.
** \param size The data size.
** \return Success: 0
**         Failure: -errno.
*/
int uhid_dev_send_input(int fd, const void *data, size_t size);

/**
** \brief Destroy an UHID USB device.
**
** \param fd The fd of the UHID USB device to destroy.
** \return Success: 0.
**         Failure: -errno.
*/
int uhid_dev_destroy(int fd);

/**
** \brief Create an UHID USB device.
**
** \param uhid_path The path of the UHID char device, should be
**                  /dev/uhid in most of the times.
** \param dev_info The device informations.
** \return Success: The fd of the UHID USB device.
**         Failure: -errno.
*/
int uhid_dev_new_with_path(const char *uhid_path,
        const struct uhid_create2_req *dev_info);

/**
** \brief Create an UHID USB device with the defautl UHID char device
**        path /dev/uhid.
**
** \param dev_info The device informations.
** \return Success: The fd of the UHID USB device.
**         Failure: -errno.
*/
int uhid_dev_new(const struct uhid_create2_req *dev_info);

#endif
