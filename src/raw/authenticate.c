#include <stdlib.h>
#include <string.h>

#include "counter.h"
#include "crypto.h"
#include "raw.h"
#include "u2f-vdev.h"


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


/**
** \brief Add user precense to the authentification response payload.
**
** \param payload The response payload.
** \param presence The presence.
*/
static void authenticate_response_user_pre(struct payload *payload,
        uint8_t presence)
{
    /* Add  to response */
    payload_add_data(payload, &presence, sizeof(presence));
}

/**
** \brief Add counter to the authentification response payload.
**
** \param payload The response payload.
** \param counter The counter.
*/
static void authenticate_response_counter(struct payload *payload,
        uint32_t counter)
{
    /* Counter */
    uint8_t counter_buffer[sizeof(uint32_t)];

    /* Fill it */
    counter_buffer[0] = counter & 0xFF;
    counter_buffer[1] = (counter >> 8) & 0xFF;
    counter_buffer[2] = (counter >> 16) & 0xFF;
    counter_buffer[3] = (counter >> 24) & 0xFF;

    /* Add to response */
    payload_add_data(payload, counter_buffer, sizeof(uint32_t));
}

/**
** \brief Add the signature to the authentification response payload.
**
** \param payload The response payload.
** \param key The key used to sign.
** \param params The authentification params.
** \param presence The user presence.
** \param counter The counter.
*/
static void authenticate_response_signature(struct payload *payload,
        EC_KEY *key,
        const struct authentification_params *params,
        uint8_t presence,
        uint32_t counter
)
{
    /* Signature */
    size_t buffer_to_sign_size =
        U2F_APP_PARAM_SIZE
        + sizeof(presence)
        + sizeof(counter)
        + U2F_CHA_PARAM_SIZE;

    /* Buffer to sign */
    uint8_t *buffer_to_sign = malloc(buffer_to_sign_size);

    /* Fill */
    size_t index = 0;
    /* App Param */
    memcpy(buffer_to_sign + index,
        &params->application_param,
        U2F_APP_PARAM_SIZE);
    index += U2F_APP_PARAM_SIZE;

    /* User precense */
    buffer_to_sign[index] = presence;
    index += sizeof(presence);

    /* Counter */
    uint8_t counter_buffer[sizeof(uint32_t)];
    /* Fill it */
    counter_buffer[0] = counter & 0xFF;
    counter_buffer[1] = (counter >> 8) & 0xFF;
    counter_buffer[2] = (counter >> 16) & 0xFF;
    counter_buffer[3] = (counter >> 24) & 0xFF;
    /* Add it */
    memcpy(buffer_to_sign + index,
        counter_buffer,
        sizeof(uint32_t));
    index += sizeof(uint32_t);

    /* Challenge Param */
    memcpy(buffer_to_sign + index,
        &params->challenge_param,
        U2F_CHA_PARAM_SIZE);
    index += U2F_CHA_PARAM_SIZE;

    /* Digest */
    uint8_t *digest = NULL;
    size_t digest_len =
        crypto_hash(buffer_to_sign, buffer_to_sign_size, &digest);

    /* Sign */
    uint8_t *signature_buffer = NULL;
    size_t signature_len =
        crypto_ec_sign_with_key(key,
                                digest,
                                digest_len,
                                &signature_buffer);

    /* Add it */
    payload_add_data(payload, signature_buffer, signature_len);

    /* Free */
    free(buffer_to_sign);
    free(digest);
    free(signature_buffer);
}

/**
** \brief Add status code to the authentification response payload.
**
** \param payload The response payload.
** \param status The status code.
*/
static void authenticate_response_sw(struct payload *payload,
        uint32_t status)
{
    /* SW */
    uint8_t sw[2] = { status >> 8, status & 0xFF };

    /* Add to response */
    payload_add_data(payload, sw, 2);
}

/**
** \brief Get the ciphered key handle from the request
**
** \param apdu The apdu data.
** \param apdu_size The apdu data size.
** \param params The authentification response.
** \param size The ref size of the ciphered key handle.
** \return The ciphered key handle.
*/
static uint8_t *authenticate_get_key_handle_cipher(
        const uint8_t *apdu, size_t apdu_size,
        const struct authentification_params *params,
        uint8_t *size)
{
    (void)apdu_size;
    /* Offset */
    size_t offset = 7
        + U2F_APP_PARAM_SIZE
        + U2F_CHA_PARAM_SIZE
        + sizeof(params->key_handle_size);

    /* Size */
    *size = params->key_handle_size;

    /* Allocate */
    uint8_t *key_handle_cipher = malloc(params->key_handle_size);

    /* Get key handle cipher */
    memcpy(key_handle_cipher, apdu + offset,
            params->key_handle_size);
    return key_handle_cipher;
}

/**
** \brief Decrypt ciphered key handle.
**
** \param crypto_core The crypto core.
** \param key_handle_cipher The ciphered key handle.
** \param key_handle_cipher_size The ciphered key handle size.
** \param size The ref size of the plain key handle.
** \return The plain key handle.
*/
static uint8_t *authenticate_decrypt_key_handle_cipher(
        struct crypto_core *crypto_core,
        const uint8_t *key_handle_cipher,
        size_t key_handle_cipher_size,
        size_t *size)
{
    /* Cipher Key handle */
    uint8_t *key_handle = NULL;
    size_t key_handle_size = crypto_aes_decrypt(
            crypto_core,
            key_handle_cipher,
            key_handle_cipher_size,
            &key_handle);

    /* Size */
    *size = key_handle_size;
    return key_handle;
}

/**
** \brief Get the pubkey from the key handle
**
** \param key_handle The plain key handle
** \param key_handle_size The plain key handle size
** \return The pubkey
*/
static EC_KEY *authenticate_get_pubkey_from_key_handle(
        const uint8_t *key_handle, size_t key_handle_size)
{

    /* Privkey */
    size_t privkey_size = key_handle_size - U2F_APP_PARAM_SIZE;
    EC_KEY *key = crypto_ec_bytes_to_key(key_handle, privkey_size);

    return key;
}

/**
** \brief Handle check authentification request.
**
** \param vdev The virtual device.
** \param apdu The apdu data.
** \param size The apdu data size.
** \return The response payload.
*/
static struct payload *raw_authenticate_check(u2f_emu_vdev *vdev,
        const uint8_t *apdu, size_t size)
{
    /* Parmas */
    struct authentification_params params;
    memcpy(&params, apdu + 7, sizeof(params));

    /* Start Response payload */
    struct payload *payload = payload_new();

    /* Key handle ciphered */
    uint8_t key_handle_cipher_size = 0;
    uint8_t *key_handle_cipher =
        authenticate_get_key_handle_cipher(apdu, size,
            &params, &key_handle_cipher_size);

    /* Key handle decrypt */
    size_t key_handle_size = 0;
    uint8_t *key_handle = authenticate_decrypt_key_handle_cipher(
        vdev->crypto_core,
        key_handle_cipher,
        key_handle_cipher_size,
        &key_handle_size
    );
    if (key_handle_size == 0)
    {
        free(key_handle_cipher);
        return NULL;
    }

    /* Privkey */
    size_t privkey_size = key_handle_size - U2F_APP_PARAM_SIZE;
    if (memcmp(key_handle + privkey_size,
            params.application_param, U2F_APP_PARAM_SIZE) != 0)
        authenticate_response_sw(payload, SW_WRONG_DATA);
    else
        authenticate_response_sw(payload,
            SW_CONDITIONS_NOT_SATISFIED);

    /* Free */
    free(key_handle_cipher);
    free(key_handle);

    return payload;
}

/**
** \brief Handle enforce authentification request.
**
** \param vdev The virtual device.
** \param apdu The apdu data.
** \param size The apdu data size.
** \return The response payload.
*/
static struct payload *raw_authenticate_enforce(u2f_emu_vdev *vdev,
        const uint8_t *apdu, size_t size)
{
    /* Parmas */
    struct authentification_params params;
    memcpy(&params, apdu + 7, sizeof(params));

    /* Start Response payload */
    struct payload *payload = payload_new();

    /* Key handle ciphered */
    uint8_t key_handle_cipher_size = 0;
    uint8_t *key_handle_cipher =
        authenticate_get_key_handle_cipher(apdu, size,
            &params, &key_handle_cipher_size);

    /* Key handle decrypt */
    size_t key_handle_size = 0;
    uint8_t *key_handle = authenticate_decrypt_key_handle_cipher(
        vdev->crypto_core,
        key_handle_cipher,
        params.key_handle_size,
        &key_handle_size
    );
    if (key_handle == NULL)
        return u2f_emu_vdev_raw_generate_error(SW_WRONG_DATA);

    /* Privkey */
    EC_KEY *key  = authenticate_get_pubkey_from_key_handle(
        key_handle, key_handle_size);

    /* User precense */
    authenticate_response_user_pre(payload, true);

    /* Counter */
    uint32_t counter_value =
            vdev->counter->counter_read(vdev->counter);
    authenticate_response_counter(payload, counter_value);

    /* Signature */
    authenticate_response_signature(payload,
        key,
        &params,
        1,
        counter_value);

    /* SW */
    authenticate_response_sw(payload, SW_NO_ERROR);

    /* Free */
    free(key_handle_cipher);
    free(key_handle);
    EC_KEY_free(key);

    /* Increment counter */
    vdev->counter->counter_increment(vdev->counter);

    return payload;
}

/**
** \brief Handle no enforce authentification request.
**
** \param vdev The virtual device.
** \param apdu The apdu data.
** \param size The apdu data size.
** \return The response payload.
*/
static struct payload *raw_authenticate_no_enforce(u2f_emu_vdev *vdev,
        const uint8_t *apdu, size_t size)
{
    (void)vdev;
    (void)apdu;
    (void)size;
    return NULL;
}

struct payload *raw_authenticate(u2f_emu_vdev *vdev,
        const uint8_t *apdu, size_t size)
{
    /* Get frame header */
    struct frame_header *header = (struct frame_header *)apdu;

    /* handle request based on type */
    switch (header->p1)
    {
    case U2F_AUTH_CHECK:
        return raw_authenticate_check(vdev, apdu, size);
    case U2F_AUTH_ENFORCE:
        return raw_authenticate_enforce(vdev, apdu, size);
    case U2F_AUTH_NO_ENFORCE:
        return raw_authenticate_no_enforce(vdev, apdu, size);
    default:
        return NULL;
    }
    /* Should not be ewecuted */

    return NULL;
}
