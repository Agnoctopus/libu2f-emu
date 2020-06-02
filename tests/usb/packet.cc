#include <stdbool.h>
#include <gtest/gtest.h>


extern "C" {
    #include "usb/cmd.h"
    #include "usb/packet.h"
}

extern bool packet_is_init(const void *packet);


TEST(PacketInit, Packet)
{
    /* Given */
    struct packet_init *packet_init = NULL;

    /* When */
    packet_init = packet_init_new(BROADCAST_CID, CMD_INIT, 0xABCD);

    /* Then */
    EXPECT_NE(packet_init, nullptr);
    EXPECT_EQ(packet_init->cid, BROADCAST_CID);
    EXPECT_EQ(packet_init->cmd, CMD_INIT);
    EXPECT_EQ(packet_init_get_bcnt(packet_init), 0xABCD);
    EXPECT_TRUE(packet_is_init(packet_init));
    EXPECT_EQ(packet_get_cid(packet_init), BROADCAST_CID);

    /* After */
    free(packet_init);
}

TEST(PacketCont, Packet)
{
    /* Given */
    struct packet_cont *packet_cont = NULL;

    /* When */
    packet_cont = packet_cont_new(BROADCAST_CID, 4);

    /* Then */
    EXPECT_NE(packet_cont, nullptr);
    EXPECT_EQ(packet_cont->cid, BROADCAST_CID);
    EXPECT_EQ(packet_cont->seq, 4);
    EXPECT_FALSE(packet_is_init(packet_cont));
    EXPECT_EQ(packet_get_cid(packet_cont), BROADCAST_CID);

    /* After */
    free(packet_cont);
}

TEST(PacketInitAdd, Packet)
{
    /* Given */
    struct packet_init *packet_init = packet_init_new(BROADCAST_CID,
            CMD_INIT, 0xABCD);;

    /* When */
    packet_init_add_bcnt(packet_init, 0x3210);

    /* Then */
    EXPECT_EQ(packet_init_get_bcnt(packet_init), 0xDDDD);


    /* After */
    free(packet_init);
}