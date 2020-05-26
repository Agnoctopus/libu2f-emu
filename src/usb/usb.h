#ifndef USB_H
#define USB_H

#include "u2f-emu.h"

void u2f_emu_vdev_usb_process(const void *packet, size_t size);

#endif