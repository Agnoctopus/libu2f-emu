#include <cstring>
#include <cstdbool>
#include <cstdint>
#include <cstdlib>
#include <gtest/gtest.h>

extern "C" {
    #include "usb/cmd.h"
    #include "usb/message.h"
    #include "usb/packet.h"
}


TEST(MessageBlank, Message)
{
    /* Given */
    struct message *message = NULL;

    /* When */
    message = message_new_blank(BROADCAST_CID, CMD_INIT);

    /* Then */
    EXPECT_NE(message, nullptr);
    EXPECT_EQ(message->bcnt, 0);
    EXPECT_EQ(message->cid, BROADCAST_CID);
    EXPECT_EQ(message->cmd, CMD_INIT);
    EXPECT_EQ(message->payload->size, 0);

    /* After */
    message_free(message);
}

TEST(MessageNew, Message)
{
    /* Given */
    struct message *message = NULL;
    struct packet_init *packet_init = packet_init_new(BROADCAST_CID,
            CMD_INIT, 42);
    memset(packet_init->data, 4, 42);

    /* When */
    message = message_new(packet_init);

    /* Then */
    EXPECT_NE(message, nullptr);
    EXPECT_EQ(message->bcnt, 42);
    EXPECT_EQ(message->cid, BROADCAST_CID);
    EXPECT_EQ(message->cmd, CMD_INIT);
    EXPECT_EQ(message->payload->size, 42);
    for (int i = 0; i < 42; ++i)
        EXPECT_EQ(message->payload->data[i], 4);

    /* After */
    free(packet_init);
    message_free(message);
}

TEST(MessageData, Message)
{
    /* Given */
    struct message *message = NULL;
    char data[42];
    memset(data, 4, 42);

    /* When */
    message = message_new_from_data(8, CMD_LOCK,
            (uint8_t *)data, 42);

    /* Then */
    EXPECT_NE(message, nullptr);
    EXPECT_EQ(message->bcnt, 42);
    EXPECT_EQ(message->cid, 8);
    EXPECT_EQ(message->cmd, CMD_LOCK);
    EXPECT_EQ(message->payload->size, 42);
    for (int i = 0; i < 42; ++i)
        EXPECT_EQ(message->payload->data[i], 4);

    /* After */
    message_free(message);
}

TEST(MessageNewMediumData, Message)
{
    /* Given */
    struct message *message = NULL;
    struct packet_init *packet_init = packet_init_new(BROADCAST_CID,
            CMD_INIT, 2048);
    memset(packet_init->data, 4, PACKET_INIT_DATA_SIZE);

    /* When */
    message = message_new(packet_init);

    /* Then */
    EXPECT_NE(message, nullptr);
    EXPECT_EQ(message->bcnt, 2048);
    EXPECT_EQ(message->cid, BROADCAST_CID);
    EXPECT_EQ(message->cmd, CMD_INIT);
    EXPECT_EQ(message->payload->size, PACKET_INIT_DATA_SIZE);
    for (int i = 0; i < PACKET_INIT_DATA_SIZE; ++i)
        EXPECT_EQ(message->payload->data[i], 4);

    /* After */
    free(packet_init);
    message_free(message);
}

TEST(MessageBlankMediumData, Message)
{
    /* Given */
    struct message *message = NULL;
    char data[2048];
    memset(data, 4, 2048);

    /* When */
    message = message_new_from_data(BROADCAST_CID, CMD_INIT,
            (uint8_t *)data, 2048);

    /* Then */
    EXPECT_NE(message, nullptr);
    EXPECT_EQ(message->bcnt, 2048);
    EXPECT_EQ(message->cid, BROADCAST_CID);
    EXPECT_EQ(message->cmd, CMD_INIT);
    EXPECT_EQ(message->payload->size, 2048);
    for (int i = 0; i < 2048; ++i)
        EXPECT_EQ(message->payload->data[i], 4);

    /* After */
    message_free(message);
}

TEST(MessageNewOverflow, Message)
{
    /* Given */
    struct message *message = NULL;
    struct packet_init *packet_init = packet_init_new(BROADCAST_CID,
            CMD_INIT, 1 << 15);

    /* When */
    message = message_new(packet_init);

    /* Then */
    EXPECT_EQ(message, nullptr);

    /* After */
    free(packet_init);
    message_free(message);
}

TEST(MessageBlankOverflow, Message)
{
    /* Given */
    struct message *message = NULL;
    char data[1 << 15];

    /* When */
    message = message_new_from_data(BROADCAST_CID, CMD_INIT,
            (uint8_t *)data, 1 << 15);

    /* Then */
    EXPECT_EQ(message, nullptr);

    /* After */
    message_free(message);
}
