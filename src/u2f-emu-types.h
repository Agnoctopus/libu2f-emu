#ifndef U2F_EMU_TYPES_H
#define U2F_EMU_TYPES_H

#include <stdint.h>


/**
** \brief U2F-emu return code.
*/
typedef enum
{
  U2F_EMU_OK = 0,
  U2F_EMU_MEMORY_ERROR,
  U2F_EMU_TRANSPORT_ERROR,
  U2F_EMU_PERMISSION_ERROR,
  U2F_EMU_SUPPORTED_ERROR
} u2f_emu_rc;

/**
** \brief U2F-emu transport emulation.
*/
typedef enum
{
  U2F_EMU_APDU = 0,
  U2F_EMU_USB,
  U2F_EMU_BLUETOOTH,
  U2F_EMU_NFC
} u2f_emu_transport;

/**
** \brief U2F-emu APDU format length.
*/
typedef enum
{
    U2F_EMU_EXTENDED = 0,
    U2F_EMU_SHORT,
} u2f_emu_apdu;

/**
** \brief U2F virtual emulated device counter structure.
*/
struct u2f_emu_vdev_counter {
  /* Get counter value */
	uint32_t (*counter_read)(struct u2f_emu_vdev_counter *counter);
  /* Increment counter value */
	void (*counter_increment)(struct u2f_emu_vdev_counter *counter);
};

/**
** \brief U2F virtual emulated device setup structure, containing all
**        necessary elements to the device setup.
*/
struct u2f_emu_vdev_setup {
	char *certificate; /**< PEM ec certificate */
	char *private_key; /**< PEM ec Private key of the certificate */
	uint8_t entropy[48]; /**< Random bits used in encryption */
  struct u2f_emu_vdev_counter *counter; /**< Counter */
};

/**
** \brief Typedef forward declaration of u2f_emu_vdev.
*/
typedef struct u2f_emu_vdev u2f_emu_vdev;

#endif
