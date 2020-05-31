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
** \param pathname The pathname of the dir
** \param crypto_core The crypto core to setup.
** \return Sucess: true.
**         Failure: false.
*/
bool crypto_setup_from_dir(const char *pathname,
        struct crypto_core *crypto_core);

/**
** \brief Release the memory allocated by the crypto_core.
**
** \param crypto_core The crypto core to release.
*/
void crypto_release(struct crypto_core *crypto_core);


#endif