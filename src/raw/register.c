#include <string.h>

#include "u2f-vdev.h"
#include "crypto.h"
#include "raw.h"


/* Params len */
#define U2F_CHA_PARAM_SIZE 32
#define U2F_APP_PARAM_SIZE 32

/**
** \brief Registration parameter
*/
struct registration_params
{
    /** SHA-256 client data */
    uint8_t challenge_param[U2F_CHA_PARAM_SIZE];
    /** SHA-256 App Id */
    uint8_t application_param[U2F_APP_PARAM_SIZE];
} __packed;


/**
** \brief Add reserved byte to the register response payload.
**
** \param payload The response payload.
*/
static void register_response_reserved(struct payload *payload)
{
    /* Reserved buffer */
    const uint8_t reserved[] = { '\x05' };

    /* Add  to response */
    payload_add_data(payload, reserved, sizeof(reserved));
}

/** \brief Add pubkey bytes to the register response.
**
** \param payload The response payload.
** \param pubkey The pubkey.
*/
static void register_response_pubkey(struct payload *payload,
        const EC_KEY *pubkey)
{
    /* Get pubkey bytes */
    uint8_t *pubkey_buffer = NULL;
    size_t pubkey_size =
        crypto_ec_pubkey_to_bytes(pubkey, &pubkey_buffer);

    /* Add to response */
    payload_add_data(payload, pubkey_buffer, pubkey_size);

    /* Free */
    free(pubkey_buffer);
}

/** \brief Add ciphered key handle to the register response payload.
**
** \param payload The response payload.
** \param key_handle_cipher The ciphered key handle
** \param key_handle_cipher_size The ciphered key handle size
*/
static void register_response_key_handle(struct payload *payload,
        const uint8_t *key_handle_cipher,
        size_t key_handle_cipher_size)
{
    /* Check size */
    if (key_handle_cipher_size > UINT8_MAX)
        return;

    /* Get size */
    uint8_t key_handle_cipher_size_byte =
        (uint8_t)key_handle_cipher_size;

    /* Add to response */
    payload_add_data(payload,
        &key_handle_cipher_size_byte,
        sizeof(key_handle_cipher_size_byte));

    payload_add_data(payload,
        key_handle_cipher,
        key_handle_cipher_size);
}

/** \brief Add x509 bytes to the register response payload.
**
** \param payload The response payload.
** \param x509_buffer The x509 buffer.
** \param x509_buffer_size The x509 buffer size.
*/
static void register_reponse_x509(struct payload *payload,
        const uint8_t *x509_buffer, size_t x509_buffer_size)
{
    /* Add to response */
    payload_add_data(payload, x509_buffer, x509_buffer_size);
}

/** \brief Add signature to the register response.
**
** \param crypto_core The crypto core.
** \param payload The response payload.
** \param key_handle_cipher The ciphered key handle.
** \param key_handle_cipher_size The ciphered key handle size.
** \param pubkey The pubkey.
** \param params The register params.
*/
static void register_response_signature(
        struct crypto_core *crypto_core,
        struct payload *payload,
        const uint8_t *key_handle_cipher,
        size_t key_handle_cipher_size,
        const EC_KEY *pubkey,
        const struct registration_params *params)
{
    /* RFU */
    uint8_t rfu = 0x00;

    /* Get pubkey bytes */
    uint8_t *pubkey_buffer = NULL;
    size_t pubkey_size =
        crypto_ec_pubkey_to_bytes(pubkey, &pubkey_buffer);

    /* Signature */
    size_t buffer_to_sign_size =
        sizeof(rfu)
        + U2F_APP_PARAM_SIZE
        + U2F_CHA_PARAM_SIZE
        + key_handle_cipher_size
        + pubkey_size;

    /* Buffer to sign */
    uint8_t *buffer_to_sign = malloc(buffer_to_sign_size);

    /* Fill */
    size_t index = 0;
    /* RFU */
    buffer_to_sign[index] = rfu;
    index += sizeof(rfu);

    /* App Param */
    memcpy(buffer_to_sign + index,
        &params->application_param,
        U2F_APP_PARAM_SIZE);
    index += U2F_APP_PARAM_SIZE;

    /* Challenge Param */
    memcpy(buffer_to_sign + index,
        &params->challenge_param,
        U2F_CHA_PARAM_SIZE);
    index += U2F_CHA_PARAM_SIZE;

    /* Key Handle */
    memcpy(buffer_to_sign + index,
        key_handle_cipher,
        key_handle_cipher_size);
    index += key_handle_cipher_size;

    /* Pubkey */
    memcpy(buffer_to_sign + index,
        pubkey_buffer,
        pubkey_size);
    index += pubkey_size;

    /* Digest */
    uint8_t *digest = NULL;
    size_t digest_len =
        crypto_hash(buffer_to_sign, buffer_to_sign_size, &digest);

    /* Sign */
    uint8_t *signature_buffer = NULL;
    size_t signature_len = crypto_ec_sign(crypto_core,
        digest,
        digest_len,
        &signature_buffer);

    /* Add to response */
    payload_add_data(payload, signature_buffer, signature_len);

    /* Free */
    free(pubkey_buffer);
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
static void register_response_sw(struct payload *payload,
        uint32_t status)
{
    /* SW */
    uint8_t sw[2] = { status >> 8, status & 0xFF };

    /* Add to response */
    payload_add_data(payload, sw, sizeof(sw));
}

/**
** \brief Build the plain key handle.
**
** \param privkey The private key.
** \param params The register params.
** \param size The ref size of the plain key handle.
** \return The plain key handle.
*/
static uint8_t *register_build_plain_key_handle(
        EC_KEY *privkey, const struct registration_params *params,
        size_t *size)
{
    /* Get privkey bytes */
    uint8_t *key_handle = NULL;
    uint8_t *key_buffer = NULL;
    size_t key_size =
        crypto_ec_key_to_bytes(privkey, &key_buffer);

    /* Size */
    size_t key_handle_size = key_size + U2F_APP_PARAM_SIZE;
    *size = key_handle_size;

    /* Allocate key_handle */
    key_handle = malloc(key_handle_size);

    /* Init key_handle */
    memcpy(key_handle, key_buffer, key_size);
    memcpy(key_handle + key_size, params->application_param,
        U2F_APP_PARAM_SIZE);

    /* Free */
    free(key_buffer);

    return key_handle;
}

/**
** \brief Encrypt the key handle.
**
** \param crypto_core The crypto core.
** \param key_handle The key handle.
** \param key_handle_size The key handle size.
** \param size The ref size of the ciphered key handle.
** \return The ciphered key handle.
*/
static uint8_t *register_encrypt_key_handle(
        struct crypto_core *crypto_core,
        const uint8_t *key_handle, size_t key_handle_size,
        size_t *size)
{
    /* Cipher Key handle */
    uint8_t *key_handle_cipher = NULL;
    size_t key_handle_cipher_size = crypto_aes_encrypt(
            crypto_core,
            key_handle,
            key_handle_size,
            &key_handle_cipher);

    /* Size */
    *size = key_handle_cipher_size;
    return key_handle_cipher;
}

struct payload *raw_register(u2f_emu_vdev *vdev,
        const uint8_t *apdu, size_t size)

{
    (void)size;
    /* Params */
    struct registration_params params;
    memcpy(&params, apdu + 7, sizeof(params));

    /* New key */
    EC_KEY *privkey = crypto_ec_generate_key();
    EC_KEY *pubkey = crypto_ec_pubkey_from_priv(privkey);

    /* Start Response payload */
    struct payload *payload = payload_new();

    /* Reserved */
    register_response_reserved(payload);

    /* Pubkey */
    register_response_pubkey(payload, pubkey);

    /* Key handle */
    size_t key_handle_size = 0;
    uint8_t *key_handle = register_build_plain_key_handle(
        privkey,
        &params,
        &key_handle_size
        );

    /* Cipher Key handle */
    size_t key_handle_cipher_size = 0;
    uint8_t *key_handle_cipher = register_encrypt_key_handle(
        vdev->crypto_core,
        key_handle,
        key_handle_size,
        &key_handle_cipher_size
    );

    /* Key handle */
    register_response_key_handle(payload,
        key_handle_cipher,
        key_handle_cipher_size);

    /* X509 */
    uint8_t *x509_buffer = NULL;
    size_t x509_buffer_size = crypto_x509_get_bytes(
            vdev->crypto_core, &x509_buffer);
    register_reponse_x509(payload, x509_buffer, x509_buffer_size);

    /* Signature */
    register_response_signature(vdev->crypto_core,
        payload,
        key_handle_cipher,
        key_handle_cipher_size,
        pubkey,
        &params);

    /* SW */
    register_response_sw(payload, SW_NO_ERROR);

    /* Free */
    EC_KEY_free(privkey);
    EC_KEY_free(pubkey);
    free(key_handle);
    free(key_handle_cipher);
    free(x509_buffer);

    return payload;
}
