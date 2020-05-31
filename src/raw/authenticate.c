#include "raw.h"

/* Authenticate bits */
#define U2F_AUTH_CHECK 0x07
#define U2F_AUTH_ENFORCE 0x03
#define U2F_AUTH_NO_ENFORCE 0x08

/* Params len */
#define U2F_CHA_PARAM_SIZE 32
#define U2F_APP_PARAM_SIZE 32

struct authentification_params
{
    /** SHA-256 client data */
    uint8_t challenge_param[U2F_CHA_PARAM_SIZE];
    /** SHA-256 App Id */
    uint8_t application_param[U2F_APP_PARAM_SIZE];
    uint8_t key_handle_size;
    uint8_t key_handle[];
} __packed;

struct payload *raw_authenticate(u2f_emu_vdev *vdev,
        const uint8_t *apdu, size_t size)
{
    (void)apdu;
    (void)size;
    return NULL;
}
