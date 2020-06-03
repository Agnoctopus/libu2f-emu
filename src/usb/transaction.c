#include "transaction.h"


bool transaction_timeout(const struct transaction *transaction)
{
    /* Time */
    time_t now_time = time(NULL);

    return now_time - transaction->start_time >= TIMEOUT_SECONDS;
}

void transaction_start(struct transaction *transaction,
        struct message *request)
{
    /* Start time */
    transaction->start_time = time(NULL);

    /* Init */
    transaction->request = request;
    transaction->response = NULL;
}
