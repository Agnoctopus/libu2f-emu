#ifndef CRYPTO
#define CRYPTO

#include <stdint.h>

#include <openssl/ec.h>
#include <openssl/x509.h>


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

X509 *crypto_x509_from_file(const char *pathname);
EC_KEY *crypto_ec_privkey_from_path(const char *pathname);

#endif