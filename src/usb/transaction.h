#ifndef TRANSACTION_H
#define TRANSaCTION_H

#include <time.h>


/**
** \brief Message timeout
*/
#define TIMEOUT_SECONDS 5

/**
** \brief Represent a transaction: a request following by a response
**        message.
*/
struct transaction
{
    time_t start_time; /**< The start time */
    struct message *request; /**< The request  */
    struct message *response; /**< The response */
};

#endif