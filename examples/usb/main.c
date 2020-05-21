#include <stdint.h>
#include <string.h>

#include "uhid-dev.h"

/**
** \brief The FIDO2/U2F UHID Descriptor
*/
const uint8_t fido_u2f_desc[] =
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
static void uhid_u2f_dev_info_init(
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
** \brief Main function of the program.
**
** \return Success: 0.
**         Failure: 1.
*/
int main(void)
{
    /* Init the device informations */
    struct uhid_create2_req dev_info;
    uhid_u2f_dev_info_init(&dev_info);

    /* Create UHID USB device */
    int fd = uhid_dev_new(&dev_info);
    if (fd < 0)
        return 1;

    /* Release */
    uhid_dev_destroy(fd);

    return 0;
}