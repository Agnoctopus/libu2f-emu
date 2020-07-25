#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>

/**
** \brief Open a file from a directory.
**
** \param dirpath The path of the directory.
** \param filename The filename.
** \param mode The mode.
** \return Success: The File handler.
**         Failure: NULL.
*/
FILE *open_file_from_dir(const char* dirpath, const char *filename,
        const char *mode);

#endif
