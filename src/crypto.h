#ifndef CRYPTO
#define CRYPTO

#include <stdbool.h>
#include <stdint.h>

#include <openssl/ec.h>
#include <openssl/x509.h>

/* Filenames */
#define CRYPTO_CERT_FILENAME "certificate.pem"
#define CRYPTO_PRIVKEY_FILENAME "private-key.pem"
#define CRYPTO_ENTROPY_FILENAME "entropy"


/**
** \brief Crypto core of the U2F device
*/
struct crypto_core
{
    X509 *cert; /**< Certificate */
    EC_KEY *privkey; /**< Private key of the certificate */
    EC_KEY *pubkey; /**< Public key of the certificate */
    uint8_t entropy[48]; /**< Random bits used in encryption */
};

/**
** \brief Get the ec key from ec key bytes.
**
** \param buffer The buffer containing the ec key bytes.
** \param size The size of the buffer.
** \return The ec key.
*/
EC_KEY *crypto_ec_bytes_to_key(const unsigned char *buffer,
        long size);

/**
** \brief Decrypt data using AES.
**
** \param crypto_core The crypto core.
** \param data The data to decrypt.
** \param size The data size.
** \param buffer The resulting buffer where clear data is put.
** \return The size of the buffer.
*/
size_t crypto_aes_decrypt(struct crypto_core* crypto_core,
        const unsigned char *data, int size,
        unsigned char **buffer);

/**
** \brief Encrypt data using AES.
**
** \param crypto_core The crypto core.
** \param data The data to encrypt.
** \param data_len The data size.
** \param buffer The resulting buffer where cipher data is put.
** \return The size of the buffer.
*/
size_t crypto_aes_encrypt(struct crypto_core* crypto_core,
        const unsigned char *data, int data_len,
        unsigned char **buffer);

/**
** \brief Get the ec key bytes.
**
** \param key The ec key.
** \param buffer The buffer use to put the bytes
** \return The size of the buffer.
*/
int crypto_ec_key_to_bytes(EC_KEY *key, unsigned char **buffer);

/**
** \brief Sign a digest with a specific key.
**
** \param key The ec key.
** \param digest The digest.
** \param digest_len The digest len.
** \param signature The ref buffer to put the signature.
** \return The size of the signature.
*/
unsigned int crypto_ec_sign_with_key(EC_KEY *key,
        const unsigned char *digest,
        int digest_len,
        unsigned char **signature);

/**
** \brief Sign a digest.
**
** \param crypto_core The crypto core.
** \param digest The digest.
** \param digest_len The digest length?
** \param signature The ref buffer to put the signature.
** \return The size of the signature.
*/
unsigned int crypto_ec_sign(struct crypto_core *crypto_core,
        const unsigned char *digest,
        int digest_len,
        unsigned char **signature);

/**
** \brief Hash data using sha256.
**
** \param data The data.
** \param data_len The data length.
** \param hash The ref buffer to put the hash.
** \return The size of the hash.
*/
size_t crypto_hash(const void *data, size_t data_len,
        unsigned char **hash);

/**
** \brief Get the ec key bytes.
**
** \param key The ec key.
** \param buffer The buffer use to put the bytes.
** \return The size of the buffer.
*/
size_t crypto_ec_pubkey_to_bytes(const EC_KEY *key,
    unsigned char **buffer);

/**
** \brief Get the x509 certificate bytes.
**
** \param crypto_core The crypto core.
** \param buffer The buffer to put the bytes.
** \return The buffer length.
*/
int crypto_x509_get_bytes(struct crypto_core *crypto_core,
        unsigned char **buffer);

/**
** \brief Get the ec public key from its private key.
**
** \param privkey the ec privkey.
** \return The ec public key
*/
EC_KEY *crypto_ec_pubkey_from_priv(EC_KEY *privkey);

/**
** \brief Generate an ec pair key.
**
** \return Success: The generated ec pair key.
**         Failure: NULL.
*/
EC_KEY *crypto_ec_generate_key(void);

/**
** \brief Setup a crypto core from a dir.
**
** \param pathname The pathname of the setup directory.
** \param crypto_core The crypto core to setup.
** \return Sucess: true.
**         Failure: false.
*/
bool crypto_setup_from_dir(const char *pathname,
        struct crypto_core *crypto_core);

/**
** \brief Setup a crypto core.
**
** \param certificate PEM ec certificate.
** \param private_key PEM ec Private key of the certificate.
** \param entropy Random bits used in encryption.
** \param crypto_core The crypto core to setup.
** \return Sucess: true.
**         Failure: false.
*/
bool crypto_setup(const char *certificate,
        const char *private_key, const uint8_t entropy[48],
        struct crypto_core *crypto_core);

/**
** \brief Release the memory allocated by the crypto_core.
**
** \param crypto_core The crypto core to release.
*/
void crypto_release(struct crypto_core *crypto_core);


#endif
