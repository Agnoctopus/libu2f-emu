#ifndef TRANSACTION_H
#define TRANSaCTION_H

#include <stdbool.h>
#include <time.h>

#include "message.h"


/**
** \brief Message timeout.
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

/**
** \brief Check if a transaction timeout.
**
** \param transaction The transaction.
** \return Timeout: true.
**         Not tiemout: false.
*/
bool transaction_timeout(const struct transaction *transaction);

/**
** \brief Start a transaction.
**
** \param transaction The transaction to start.
** \param request The corresponding request message.
*/
void transaction_start(struct transaction *transaction,
        struct message *request);


#endif