#ifndef U2F_DEV_H
#define U2F_DEV_H

#include <u2f-emu.h>

#include "uhid-dev.h"


/**
** \brief U2F USB emulated virtuel device
*/
typedef struct u2f_usb_emu_vdev u2f_usb_emu_vdev;

/**
** \brief Create an UHID USB U2F device with the default UHID char
**        device path /dev/uhid and an U2F virtual emulated device.
**
** \param vdev The U2F virtual emulated device.
** \param vdev_usb The U2F USB virtual emulated device reference.
** \return Success: 0.
**         Failure: -errno.
*/
int u2f_dev_new(u2f_emu_vdev *vdev,
        u2f_usb_emu_vdev **vdev_usb_ref);

/**
** \brief Create an UHID USB U2F device.
**
** \param uhid_path The path of the UHID char device, should be
**                  /dev/uhid in most of the times and an U2F
**                  virtual emulated device.
** \param vdev The U2F virtual emulated device.
** \param vdev_usb The U2F USB virtual emulated device reference.
** \return Success: 0.
**         Failure: -errno.
*/
int u2f_dev_new_with_path(const char *uhid_path,
        u2f_emu_vdev *vdev, u2f_usb_emu_vdev **vdev_usb_ref);

/**
** \brief Free an U2F USB virtual emulated device.
**
** \param vdev_usb Virtual device.
*/
void u2f_dev_free(u2f_usb_emu_vdev *vdev_usb);

/**
** \brief Run an emulated UHID USB U2F device.
**
** \param fd The fd of the UHID USB U2F device.
** \param vdef The U2F virtual emulated device.
** \return Success: 0
**         Failure: -1
*/
int u2f_dev_usb_run(const u2f_usb_emu_vdev *usb_vdev);

#endif