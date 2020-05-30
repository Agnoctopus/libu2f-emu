#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/pem.h>

#include "crypto.h"


/**
** \brief Open a file.
**
** \param pathname The pathname of the file.
** \return Success: The File handler.
**         Failure: NULL.
*/
static FILE *crypto_open(const char *pathname)
{
    /* Open */
    int fd = open(pathname, O_RDONLY | O_CLOEXEC);
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
** \param pathname The pathname of the x509 key.
** \return Success: The x509.
**         Failure: NULL.
*/
X509 *crypto_x509_from_file(const char *pathname)
{
    /* Open */
    FILE *fp = crypto_open(pathname);
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
** \param pathname The pathname of the ec private key.
** \return Success: The private key.
**         Failure: NULL.
*/
EC_KEY *crypto_ec_privkey_from_path(const char *pathname)
{
    /* Open */
    FILE *fp = crypto_open(pathname);
    if (fp == NULL)
        return NULL;

    /* EC_Key */
    EC_KEY *privkey = EC_KEY_new();
    privkey = PEM_read_ECPrivateKey(fp, &privkey, NULL, NULL);

    /* Close */
    fclose(fp);

    return privkey;
}