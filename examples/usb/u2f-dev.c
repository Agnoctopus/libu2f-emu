#include <err.h>
#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "u2f-dev.h"

/**
** \brief U2F USB emulated virtuel device
*/
struct u2f_usb_emu_vdev
{
    int fd; /**< fd of the UHID USB U2F device. */
    u2f_emu_vdev *vdev; /**< U2F virtual emulated device. */
};

/**
** \brief The FIDO2/U2F UHID Descriptor
*/
static const uint8_t fido_u2f_desc[] =
{
    0x06, 0xD0, 0xF1, /* USAGE_PAGE (FIDO_USAGE_PAGE) */
    0x09, 0x01,       /* USAGE (FIDO_USAGE_PAGE) */
    0xA1, 0x01,       /* COLLECTION (HID_APPLICATION)*/
    0x09, 0x20,       /* USAGE (FIDO_USAGE_DATA_IN) */
    0x15, 0x00,       /* LOGICAL_MINIMUM (0) */
    0x26, 0xFF, 0x00, /* LOGICAL_MAXIMUM (OxFF) */
    0x75, 0x08,       /* REPORT_SIZE (8) */
    0x95, 0x40,       /* REPORT_COUNT (HID_INPUT_REPORT_BYTES) */
    0x81, 0x02,       /* INPUT (Data,Var,Abs) */
    0x09, 0x21,       /* USAGE (FIDO_USAGE_DATA_OUT) */
    0x15, 0x00,       /* LOGICAL_MINIMUM (0) */
    0x26, 0xFF, 0x00, /* LOGICAL_MAXIMUM  (OxFF) */
    0x75, 0x08,       /* REPORT_SIZE (8) */
    0x95, 0x40,       /* REPORT_COUNT (HID_OUTPUT_REPORT_BYTES) */
    0x91, 0x02,       /* OUTPUT (Data,Var,Abs) */
    0xC0              /* END_COLLECTION */
};


/**
** \brief Init the device informations needed to create
**        an U2F UHID USB device.
**
** \param dev_info The device informations de init.
*/
static void u2f_dev_uhid_info_init(
        struct uhid_create2_req *dev_info)
{
    /* Wipe the device informations */
    memset(dev_info, 0, sizeof(struct uhid_create2_req));

    /* Name, phys, uniq */
    strcpy((char *)dev_info->name, "Virtual FIDO/U2F security Key");
    strcpy((char *)dev_info->phys, "");
    strcpy((char *)dev_info->uniq, "");

    /* Vendor, product, version, country */
    dev_info->vendor = 0xFFFF;
    dev_info->product = 0xFFFF;
    dev_info->version = 0;
    dev_info->country = 0;

    /* UHID USB desc */
    dev_info->bus = BUS_USB;
    dev_info->rd_size = sizeof(fido_u2f_desc);
    memcpy(dev_info->rd_data, fido_u2f_desc,
            sizeof(fido_u2f_desc));
}

/**
** \brief Handler for incoming UHDI event for an U2F UHID
**        USB device.
**
** \param dev_info The device informations de init.
*/
static void u2f_dev_uhid_event_handler(
        const u2f_usb_emu_vdev *vdev_usb)
{
    /* Get the event */
    struct uhid_event event;
    uhid_dev_recv_event(vdev_usb->fd, &event);

    /* Handle only UHID_OUTPUT */
    if (event.type != UHID_OUTPUT)
        return;

    /* Get the packet */
    const void *packet = event.u.output.data + 1;
    size_t packet_size = event.u.output.size - 1;

    /* Handle packet */
    u2f_emu_vdev_process(vdev_usb->vdev, packet, packet_size);
}

int u2f_dev_usb_run(const u2f_usb_emu_vdev *usb_vdev)
{
    /* Setup the poll structure */
    struct pollfd pfds[1];
    pfds[0].fd = usb_vdev->fd;
    pfds[0].events = POLLIN;

    /* Poll infinitelly the device */
    while (true)
    {
        /* Poll */
        int ret = poll(pfds, 1, -1);

        /* Error */
        if (ret < 0)
        {
            warn("Cannot poll the virtual device.");
            return 1;
        }

        /* HUP */
        if (pfds[0].revents & POLLHUP)
        {
            warn("Received HUP on virtual device.");
            break;
        }

        /* Input event */
        if (pfds[0].revents & POLLIN)
            u2f_dev_uhid_event_handler(usb_vdev);
    }

    /* HUP */
    return 0;
}

int u2f_dev_new_with_path(const char *uhid_path,
        u2f_emu_vdev *vdev, u2f_usb_emu_vdev **vdev_usb_ref)
{
    /* Allocate */
    u2f_usb_emu_vdev *vdev_usb = malloc(sizeof(u2f_usb_emu_vdev));
    if (vdev_usb == NULL)
    {
        warn("Failed to allocate the virtual U2F USB device.");
        return -errno;
    }
    /* Init the device informations */
    struct uhid_create2_req dev_info;
    u2f_dev_uhid_info_init(&dev_info);

    /* Create UHID USB device */
    int fd = uhid_dev_new_with_path(uhid_path, &dev_info);

    /* Check error */
    if (fd < 0)
    {
        /* Log */
        warnx("Failed to create a new UHID USB U2F device.");

        /* Release */
        free(vdev_usb);
        return fd;
    }

    /* Initialize */
    vdev_usb->fd = fd;
    vdev_usb->vdev = vdev;

    /* Reference */
    *vdev_usb_ref = vdev_usb;

    return 0;
}

int u2f_dev_new(u2f_emu_vdev *vdev,
        u2f_usb_emu_vdev **vdev_usb_ref)
{
    /* Delegate */
    return u2f_dev_new_with_path("/dev/uhid",
            vdev, vdev_usb_ref);
}

void u2f_dev_free(u2f_usb_emu_vdev *vdev_usb)
{
    /* Release */
    uhid_dev_destroy(vdev_usb->fd);
    free(vdev_usb);
}
