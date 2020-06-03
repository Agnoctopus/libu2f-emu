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

TEST(MessagePart, Message)
{
    /* Given */
    struct message *message = NULL;
    struct packet_init *packet_init =
            packet_init_new(BROADCAST_CID, CMD_INIT,
                    PACKET_INIT_DATA_SIZE + 42);
    struct packet_cont *packet_cont =
            packet_cont_new(BROADCAST_CID, 0);
    memset(packet_init->data, 4, PACKET_INIT_DATA_SIZE);
    memset(packet_cont->data, 8, 42);
    message = message_new(packet_init);

    /* When */
    bool ret = message_add_part(message, packet_cont);

    /* Then */
    EXPECT_TRUE(ret);
    for (int i = 0; i < PACKET_INIT_DATA_SIZE; ++i)
        EXPECT_EQ(message->payload->data[i], 4);
    for (int i = PACKET_INIT_DATA_SIZE;
            i < PACKET_INIT_DATA_SIZE + 42; ++i)
        EXPECT_EQ(message->payload->data[i], 8);

    /* After */
    free(packet_init);
    free(packet_cont);
    message_free(message);
}


TEST(MessagePartBadCID, Message)
{
    /* Given */
    struct message *message = NULL;
    struct packet_init *packet_init =
            packet_init_new(BROADCAST_CID, CMD_INIT, 84);
    struct packet_cont *packet_cont =
            packet_cont_new(4, 0);
    message = message_new(packet_init);

    /* When */
    bool ret = message_add_part(message, packet_cont);

    /* Then */
    EXPECT_FALSE(ret);

    /* After */
    free(packet_init);
    free(packet_cont);
    message_free(message);
}

TEST(MessagePartOneInit, Message)
{
    /* Given */
    struct message *message = NULL;
    struct packet_init *packet_init =
            packet_init_new(BROADCAST_CID, CMD_INIT, 42);
    struct packet_cont *packet_cont =
            packet_cont_new(BROADCAST_CID, 0);
    message = message_new(packet_init);

    /* When */
    bool ret = message_add_part(message, packet_cont);

    /* Then */
    EXPECT_FALSE(ret);

    /* After */
    free(packet_init);
    free(packet_cont);
    message_free(message);
}

TEST(MessagePartBadSeq, Message)
{
    /* Given */
    struct message *message = NULL;
    struct packet_init *packet_init =
            packet_init_new(BROADCAST_CID, CMD_INIT, 84);
    struct packet_cont *packet_cont =
            packet_cont_new(BROADCAST_CID, 1);
    message = message_new(packet_init);

    /* When */
    bool ret = message_add_part(message, packet_cont);

    /* Then */
    EXPECT_FALSE(ret);

    /* After */
    free(packet_init);
    free(packet_cont);
    message_free(message);
}

TEST(MessageOverflow, Message)
{
    /* Given */
    struct message *message = NULL;
    struct packet_init *packet_init =
            packet_init_new(BROADCAST_CID, CMD_INIT, 84);
    struct packet_cont *packet_cont =
            packet_cont_new(BROADCAST_CID, 0);
    struct packet_cont *packet_cont_next =
            packet_cont_new(BROADCAST_CID, 0);
    message = message_new(packet_init);
    message_add_part(message, packet_cont);

    /* When */
    bool ret = message_add_part(message, packet_cont_next);

    /* Then */
    EXPECT_FALSE(ret);

    /* After */
    free(packet_init);
    free(packet_cont);
    free(packet_cont_next);
    message_free(message);
}

TEST(MessageNextOnePacket, Message)
{
    /* Given */
    struct message *message = NULL;
    char data[42];
    memset(data, 4, 42);
    message = message_new_from_data(BROADCAST_CID, CMD_INIT,
            (uint8_t *)data, 42);
    struct packet_init *packet_init = NULL;

    /* When */
    bool ret = message_next_packet(message, (void **)&packet_init);

    /* Then */
    EXPECT_FALSE(ret);
    EXPECT_EQ(packet_init->cid, BROADCAST_CID);
    EXPECT_EQ(packet_init->cmd, CMD_INIT);
    EXPECT_EQ(packet_init_get_bcnt(packet_init), 42);
    for (int i = 0; i < 42; ++i)
        EXPECT_EQ(packet_init->data[i], 4);

    /* After */
    free(packet_init);
    message_free(message);
}

TEST(MessageNextTwoPackets, Message)
{
    /* Given */
    struct message *message = NULL;
    char data[84];
    memset(data, 4, 84);
    message = message_new_from_data(BROADCAST_CID, CMD_INIT,
            (uint8_t *)data, 84);
    struct packet_init *packet_init = NULL;
    struct packet_cont *packet_cont = NULL;

    /* When */
    bool ret1 = message_next_packet(message, (void **)&packet_init);
    bool ret2 = message_next_packet(message, (void **)&packet_cont);

    /* Then */
    EXPECT_TRUE(ret1);
    EXPECT_FALSE(ret2);
    EXPECT_EQ(packet_init->cid, BROADCAST_CID);
    EXPECT_EQ(packet_init->cmd, CMD_INIT);
    EXPECT_EQ(packet_init_get_bcnt(packet_init), 84);
    for (int i = 0; i < PACKET_INIT_DATA_SIZE; ++i)
        EXPECT_EQ(packet_init->data[i], 4);
    EXPECT_EQ(packet_cont->cid, BROADCAST_CID);
    EXPECT_EQ(packet_cont->seq, 0);
    for (int i = 0; i < 84 - PACKET_INIT_DATA_SIZE; ++i)
        EXPECT_EQ(packet_cont->data[i], 4);

    /* After */
    free(packet_init);
    free(packet_cont);
    message_free(message);
}

TEST(MessageNextThreePackets, Message)
{
    /* Given */
    struct message *message = NULL;
    char data[128];
    memset(data, 4, 128);
    message = message_new_from_data(BROADCAST_CID, CMD_INIT,
            (uint8_t *)data, 128);
    struct packet_init *packet_init = NULL;
    struct packet_cont *packet_cont = NULL;
    struct packet_cont *packet_cont_next = NULL;

    /* When */
    bool ret1 = message_next_packet(message, (void **)&packet_init);
    bool ret2 = message_next_packet(message, (void **)&packet_cont);
    bool ret3 = message_next_packet(message,
            (void **)&packet_cont_next);

    /* Then */
    EXPECT_TRUE(ret1);
    EXPECT_TRUE(ret2);
    EXPECT_FALSE(ret3);
    EXPECT_EQ(packet_cont->cid, BROADCAST_CID);
    EXPECT_EQ(packet_cont->seq, 0);
    for (int i = 0; i < PACKET_INIT_DATA_SIZE; ++i)
        EXPECT_EQ(packet_cont->data[i], 4);
    EXPECT_EQ(packet_cont_next->cid, BROADCAST_CID);
    EXPECT_EQ(packet_cont_next->seq, 1);
    for (int i = 0; i < 128 - PACKET_INIT_DATA_SIZE
            - PACKET_CONT_DATA_SIZE; ++i)
        EXPECT_EQ(packet_cont->data[i], 4);

    /* After */
    free(packet_init);
    free(packet_cont);
    free(packet_cont_next);
    message_free(message);
}
