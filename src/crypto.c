#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/pem.h>

#include "crypto.h"


/**
** \brief Compute the PEM length.
**
** \param pem The PEM.
** \return Success: PEM length.
**         Failure: 0.
*/
static size_t crypto_pem_length(const char *pem)
{
    size_t length = 0;
    if (pem[length] != '-')
        return 0;
    ++length;
    /* Skip - */
    for (int i = 0; i < 3; ++i)
    {
        /* Skip - */
        while (pem[length] == '-')
            ++length;
        /* Skip letters */
        while (pem[length] != '-')
            ++length;
    }
    /* Skip - */
    while (pem[length] == '-')
        ++length;
    return length;
}

EC_KEY *crypto_ec_bytes_to_key(const unsigned char *buffer,
    long size)
{
    /* prepare curve and key */
    EC_KEY *key = NULL;

    /* Get key */
    key = d2i_ECPrivateKey(&key, &buffer, size);
    return key;
}

size_t crypto_aes_decrypt(struct crypto_core* crypto_core,
        const unsigned char *data, int size,
        unsigned char **buffer)
{
    /* Cipher context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return 0;

    /* Init operation */
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(),
        NULL, NULL, NULL) != 1)
    {
        /* Release  */
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    /* Init and key */
    if (EVP_DecryptInit_ex(ctx, NULL, NULL,
            crypto_core->entropy, crypto_core->entropy + 32) != 1)
    {
        /* Free */
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    /* Allocate */
    *buffer = malloc(size + 32);
    int len = 0;
    size_t result_len = 0;

    /* Decrypr */
    if (EVP_DecryptUpdate(ctx, *buffer, &len, data, size) != 1)
    {
        /* Free */
        EVP_CIPHER_CTX_free(ctx);
        free(*buffer);

        return 0;
    }
    result_len = len;

    if (EVP_DecryptFinal_ex(ctx, (*buffer) + len, &len) != 1)
    {
        /* Free */
        EVP_CIPHER_CTX_free(ctx);
        free(*buffer);

        return 0;
    }
    result_len += len;

    /* Free */
    EVP_CIPHER_CTX_free(ctx);

    return result_len;
}

size_t crypto_aes_encrypt(struct crypto_core* crypto_core,
        const unsigned char *data, int data_len,
        unsigned char **buffer)
{
    /* Cipher context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return 0;

    /* Init operation */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(),
        NULL, NULL, NULL) != 1)
    {
        /* Release */
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    /* Init and key */
    if (EVP_EncryptInit_ex(ctx, NULL,
        NULL, crypto_core->entropy, crypto_core->entropy + 32) != 1)
    {
        /* Release */
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    /* Allocate */
    *buffer = malloc(data_len + 32);
    int len = 0;

    /* Encrypt */
    if (EVP_EncryptUpdate(ctx, *buffer, &len, data, data_len) != 1)
    {
        /* Free */
        EVP_CIPHER_CTX_free(ctx);
        free(*buffer);

        return 0;
    }
    size_t result_len = len;

    if (EVP_EncryptFinal_ex(ctx, (*buffer) + len, &len) != 1)
    {
        /* Free */
        EVP_CIPHER_CTX_free(ctx);
        free(*buffer);

        return 0;
    }
    result_len += len;

    /* Free */
    EVP_CIPHER_CTX_free(ctx);

    return result_len;;
}

int crypto_ec_key_to_bytes(EC_KEY *key, unsigned char **buffer)
{
    /* Reset buffer ref */
    *buffer = NULL;

    /* Get bytes */
    return i2d_ECPrivateKey(key, buffer);
}

unsigned int crypto_ec_sign_with_key(EC_KEY *key,
    const unsigned char *digest,
    int digest_len,
    unsigned char **signature)
{
    /* Signature length  */
    *signature = NULL;
    int ret_size = ECDSA_size(key);
    if (ret_size <= 0)
        return 0;

    unsigned int signature_len = ret_size;

    /* Signature buffer */
    *signature = OPENSSL_malloc(signature_len);
    if (*signature == NULL)
        return 0;

    /* Sign */
    int sign_ret = ECDSA_sign(0,
            digest,
            digest_len,
            *signature,
            &signature_len,
            key);

    /* Sign check */
    if (sign_ret != 1)
    {
        /* Release */
        free(*signature);
        *signature = NULL;
        return 0;
    }

    /* Verify the signature */
    int verify_ret = ECDSA_verify(0,
            digest,
            digest_len,
            *signature,
            signature_len,
            key);

    /* Verify check */
    if (verify_ret != 1)
    {
        /* Release */
        free(*signature);
        *signature = NULL;
        return 0;
    }
    return signature_len;
}

unsigned int crypto_ec_sign(struct crypto_core *crypto_core,
    const unsigned char *digest,
    int digest_len,
    unsigned char **signature)
{
    return crypto_ec_sign_with_key(crypto_core->privkey,
        digest, digest_len, signature);
}

size_t crypto_hash(const void *data, size_t data_len,
        unsigned char **hash)
{
    /* Init */
    SHA256_CTX sha256;
    if (SHA256_Init(&sha256) != 1)
        return 0;

    /* Allocate hash buffer */
    *hash = malloc(SHA256_DIGEST_LENGTH);

    /* Update */
    if (SHA256_Update(&sha256, data, data_len) != 1)
    {
        /* Release */
        free(hash);
        return 0;
    }

    /* Finish */
    if(SHA256_Final(*hash, &sha256) != 1)
    {
        /* Release */
        free(hash);
        return 0;
    }
    return SHA256_DIGEST_LENGTH;
}

size_t crypto_ec_pubkey_to_bytes(const EC_KEY *key,
    unsigned char **buffer)
{
    /* bignum context */
    BN_CTX *bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        return 0;

    size_t size = EC_KEY_key2buf(key,
            POINT_CONVERSION_UNCOMPRESSED,
            buffer,
            bn_ctx);

    /* Free */
    BN_CTX_free(bn_ctx);
    return size;
}

int crypto_x509_get_bytes(struct crypto_core *crypto_core,
        unsigned char **buffer)
{
    /* Reset buffer ref */
    *buffer = NULL;

    /* Delegate */
    return i2d_X509(crypto_core->cert, buffer);
}

EC_KEY *crypto_ec_generate_key(void)
{
    /* Prepare ec key */
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (key == NULL)
        return NULL;

    /* Generate */
    if (EC_KEY_generate_key(key) != 1)
    {
        /* Release */
        EC_KEY_free(key);
        return NULL;
    }
    return key;
}

/**
** \brief Open a file.
**
** \param dirfd The dirfd to get pathname file.
** \param pathname The pathname of the file.
** \return Success: The File handler.
**         Failure: NULL.
*/
static FILE *crypto_open(int dirfd, const char *pathname)
{
    /* Open */
    int fd = openat(dirfd, pathname, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return NULL;

    /* Fdopen */
    FILE * fp = fdopen(fd, "rb");
    if (fp == NULL)
    {
        close(fd);
        return NULL;
    }
    return fp;
}

/**
** \brief Get the x509 from file.
**
** \param dirfd The dirfd to get pathname file.
** \param pathname The pathname of the x509 key.
** \return Success: The x509.
**         Failure: NULL.
*/
static X509 *crypto_x509_from_file(int dirfd,
        const char *pathname)
{
    /* Open */
    FILE *fp = crypto_open(dirfd, pathname);
    if (fp == NULL)
        return NULL;

    /* X509 */
    X509 *x509 = X509_new();
    x509 = PEM_read_X509(fp, &x509, NULL, NULL);

    /* Close */
    fclose(fp);

    return x509;
}

/**
** \brief Get the x509 from PEM.
**
** \param x509_pem The x509 PEM.
** \return Success: The x509.
**         Failure: NULL.
*/
static X509 *crypto_x509_from_pem(const char *x509_pem)
{
    /* Pem length */
    size_t pem_length = crypto_pem_length(x509_pem);
    if (pem_length == 0)
        return NULL;

    /* Bio needed */
    BIO *x509_bio = BIO_new(BIO_s_mem());
    if (x509_bio == NULL)
        return NULL;
    BIO_write(x509_bio, x509_pem, pem_length);

    /* x509 */
    X509 *x509 = X509_new();
    PEM_read_bio_X509(x509_bio, &x509, NULL, NULL);

    /* Free */
    BIO_free_all(x509_bio);

    return x509;
}

/**
** \brief Get the ec private key from path
**
** \param dirfd The dirfd to get pathname file.
** \param pathname The pathname of the ec private key.
** \return Success: The private key.
**         Failure: NULL.
*/
static EC_KEY *crypto_ec_privkey_from_path(int dirfd,
        const char *pathname)
{
    /* Open */
    FILE *fp = crypto_open(dirfd, pathname);
    if (fp == NULL)
        return NULL;

    /* EC_Key */
    EC_KEY *privkey = EC_KEY_new();
    privkey = PEM_read_ECPrivateKey(fp, &privkey, NULL, NULL);

    /* Close */
    fclose(fp);

    return privkey;
}

/**
** \brief Get the ec private key from PEM.
**
** \param private_key_pem The ec private key PEM.
** \return Success: The private key.
**         Failure: NULL.
*/
static EC_KEY *crypto_ec_privkey_from_pem(
        const char *private_key_pem)
{
    /* Pem length */
    size_t pem_length = crypto_pem_length(private_key_pem);
    if (pem_length == 0)
        return NULL;

    /* Bio needed */
    BIO *privkey_bio = BIO_new(BIO_s_mem());
    if (privkey_bio == NULL)
        return NULL;
    BIO_write(privkey_bio, private_key_pem, pem_length);

    /* EC_Key */
    EC_KEY *privkey = EC_KEY_new();
    PEM_read_bio_ECPrivateKey(privkey_bio, &privkey, NULL, NULL);

    /* Free */
    BIO_free_all(privkey_bio);

    return privkey;
}

/**
** \brief Setup the entropy part of the crypto core.
**
** \param dirfd The dirfd to get pathname file.
** \param pathname The pathname of the entropy bits.
** \param crypto_core The crypto core.
*/
static bool crypto_setup_entropy(int dirfd, const char *pathname,
        struct crypto_core *crypto_core)
{
    /* Open */
    FILE *fp = crypto_open(dirfd, pathname);
    if (fp == NULL)
        return false;

    /* Read entropy */
    bool ok = fread(&crypto_core->entropy, 48, 1, fp) == 1;

    /* Close */
    fclose(fp);

    return ok;
}

EC_KEY *crypto_ec_pubkey_from_priv(EC_KEY *privkey)
{
    /* Bio needed */
    BIO *pubkeybio = BIO_new(BIO_s_mem());
    if (pubkeybio == NULL)
        return NULL;

    /* Write pubkey to the bio  */
    if (PEM_write_bio_EC_PUBKEY(pubkeybio, privkey) != 1)
    {
        /* Release */
        BIO_free_all(pubkeybio);
        return NULL;
    }

    /* Get pubkey */
    EC_KEY *pubkey = EC_KEY_new() ;
    pubkey = PEM_read_bio_EC_PUBKEY(pubkeybio, &pubkey, NULL, NULL);

    /* Free */
    BIO_free_all(pubkeybio);
    return pubkey;
}

bool crypto_setup(const char *certificate,
        const char *private_key, const uint8_t entropy[48],
        struct crypto_core *crypto_core)
{
    /* Entropy */
    memcpy(crypto_core->entropy, entropy, 48);

    /* Certificate */
    crypto_core->cert = crypto_x509_from_pem(certificate);
    if (crypto_core->cert == NULL)
        return false;

    /* Private key */
    crypto_core->privkey = crypto_ec_privkey_from_pem(private_key);
    if (crypto_core->privkey == NULL)
        return false;

    /* Pub key */
    crypto_core->pubkey =
            crypto_ec_pubkey_from_priv(crypto_core->privkey);
    if (crypto_core->pubkey == NULL)
        return false;
    return true;
}

bool crypto_setup_from_dir(const char *pathname,
        struct crypto_core *crypto_core)
{
    /* Open dir */
    int dirfd = openat(AT_FDCWD, pathname,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0)
        return false;

    /* Entropy */
    if (!crypto_setup_entropy(dirfd, CRYPTO_ENTROPY_FILENAME,
            crypto_core))
    {
        close(dirfd);
        return false;
    }

    /* Certificate */
    crypto_core->cert =
            crypto_x509_from_file(dirfd, CRYPTO_CERT_FILENAME);
    if (crypto_core->cert == NULL)
    {
        close(dirfd);
        return false;
    }

    /* Private key */
    crypto_core->privkey = crypto_ec_privkey_from_path(dirfd,
            CRYPTO_PRIVKEY_FILENAME);
    close(dirfd);
    if (crypto_core->privkey == NULL)
        return false;

    /* Pub key */
    crypto_core->pubkey =
            crypto_ec_pubkey_from_priv(crypto_core->privkey);
    if (crypto_core->pubkey == NULL)
        return false;

    /* Close */
    close(dirfd);

    return true;
}


void crypto_release(struct crypto_core *crypto_core)
{
    X509_free(crypto_core->cert);
    EC_KEY_free(crypto_core->pubkey);
    EC_KEY_free(crypto_core->privkey);
}
