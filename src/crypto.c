#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/pem.h>

#include "crypto.h"


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
    if (crypto_core->privkey == NULL)
    {
        close(dirfd);
        return false;
    }

    /* Pub key */
    crypto_core->pubkey =
            crypto_ec_pubkey_from_priv(crypto_core->privkey);
    if (crypto_core->pubkey == NULL)
    {
        close(dirfd);
        return false;
    }

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
