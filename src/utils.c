#include <stdlib.h>
#include <string.h>

#include "utils.h"


FILE *open_file_from_dir(const char* dirpath, const char *filename,
        const char *mode)
{
    /* Allocate pathname */
    size_t dirpath_len = strlen(dirpath);
    char *pathname = malloc(dirpath_len + strlen(filename) + 2);
    if (pathname == NULL)
        return NULL;

    /* Compute pathname */
    strcpy(pathname, dirpath);
    pathname[dirpath_len] = '/';
    strcpy(pathname + dirpath_len + 1, filename);

    /* Open */
    FILE *fp = fopen(pathname, mode);

    /* Release */
    free(pathname);

    return fp;
}
