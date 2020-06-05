#ifndef U2F_EMU_TYPES_H
#define U2F_EMU_TYPES_H

typedef enum
{
  U2F_EMU_OK = 0,
  U2F_EMU_MEMORY_ERROR,
  U2F_EMU_TRANSPORT_ERROR,
  U2F_EMU_PERMISSION_ERROR,
  U2F_EMU_SUPPORTED_ERROR
} u2f_emu_rc;

typedef enum
{
  U2F_EMU_APDU = 0,
  U2F_EMU_USB,
  U2F_EMU_BLUETOOTH,
  U2F_EMU_NFC
} u2f_emu_transport;

typedef enum
{
    U2F_EMU_EXTENDED = 0,
    U2F_EMU_SHORT,
} u2f_emu_apdu;

typedef struct u2f_emu_vdev u2f_emu_vdev;

#endif
