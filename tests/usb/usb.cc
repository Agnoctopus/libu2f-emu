#include <cstring>
#include <cstdbool>
#include <cstdint>
#include <cstdlib>
#include <gtest/gtest.h>

extern "C" {
    #include "u2f-emu.h"
    #include "usb/message.h"
    #include "usb/cmd.h"
    #include "raw/raw.h"
}


#define SETUP_DIR "../.u2f.tmp"


TEST(NoResponse, USB)
{
    /* Given */
    u2f_emu_vdev *vdev = NULL;
    u2f_emu_vdev_new(&vdev, U2F_EMU_USB, SETUP_DIR);

    /* When */
    bool ret = u2f_emu_vdev_has_response(vdev);

    /* Then */
    EXPECT_FALSE(ret);

    /* After */
    u2f_emu_vdev_free(vdev);
}

static bool usb_send_request(u2f_emu_vdev *vdev,
        struct message *request)
{
    /* Packet and end variables */
    void *packet = NULL;
    bool end = false;

    /* Loop while not request end */
    while (!end)
    {
        /* Get next packet */
        end = !message_next_packet(request, &packet);

        /* Process it */
        u2f_emu_rc rc = u2f_emu_vdev_process(vdev, packet,
                PACKET_SIZE);
        if (rc != U2F_EMU_OK)
            return false;

        /* Release */
        free(packet);
    }
    return true;
}

static struct message *usb_recv_response(u2f_emu_vdev *vdev)
{
    /* Get init packet */
    struct packet_init *packet_init = NULL;
    size_t size = u2f_emu_vdev_get_response(vdev,
            (uint8_t **)&packet_init);
    if (size != PACKET_SIZE)
        return NULL;

    /* Response message */
    struct message *response = message_new(packet_init);
    if (response == NULL)
        return NULL;
    free(packet_init);

    /* Fill message */
    struct packet_cont *packet_cont = NULL;
    while (u2f_emu_vdev_has_response(vdev))
    {
        /* Get next response part */
        size = u2f_emu_vdev_get_response(vdev,
                (uint8_t **)&packet_cont);
        if (size != PACKET_SIZE)
        {
            message_free(response);
            return NULL;
        }
        if (!message_add_data(response, packet_cont->data,
                PACKET_CONT_DATA_SIZE))
        {
            message_free(response);
            return NULL;
        }
        free(packet_cont);
    }

    return response;
}


TEST(InitOut, USB)
{
    /* Given */
    u2f_emu_vdev *vdev = NULL;
    u2f_emu_vdev_new(&vdev, U2F_EMU_USB, SETUP_DIR);

    const char *nonce = "ABCDEFGF";
    struct message *request = message_new_from_data(BROADCAST_CID,
            CMD_INIT, (uint8_t *)nonce, strlen(nonce));

    /* When */
    bool ret = usb_send_request(vdev, request);

    /* Then */
    EXPECT_TRUE(ret);
    EXPECT_TRUE(u2f_emu_vdev_has_response(vdev));

    /* After */
    message_free(request);
    u2f_emu_vdev_free(vdev);
}

TEST(InitIn, USB)
{
    /* Given */
    u2f_emu_vdev *vdev = NULL;
    u2f_emu_vdev_new(&vdev, U2F_EMU_USB, SETUP_DIR);

    const char *nonce = "ABCDEFGF";
    struct message *request = message_new_from_data(BROADCAST_CID,
            CMD_INIT, (uint8_t *)nonce, 8);

    usb_send_request(vdev, request);

    /* When */
    struct message *response = usb_recv_response(vdev);

    /* Then */
    EXPECT_NE(response, nullptr);
    EXPECT_EQ(response->payload->size, 17);
    EXPECT_FALSE(u2f_emu_vdev_has_response(vdev));
    for (int i = 0; i < 8; ++i)
        EXPECT_EQ(response->payload->data[i], nonce[i]);
    uint32_t cid = ((uint32_t *)response->payload->data)[3];
    EXPECT_NE(cid, BROADCAST_CID);
    EXPECT_EQ(response->payload->data[12], 2);
    EXPECT_EQ(response->payload->data[13], 0);
    EXPECT_EQ(response->payload->data[14], 1);
    EXPECT_EQ(response->payload->data[15], 0);

    /* After */
    message_free(request);
    message_free(response);
    u2f_emu_vdev_free(vdev);
}

TEST(VersionOut, USB)
{
    /* Given */
    u2f_emu_vdev *vdev = NULL;
    u2f_emu_vdev_new(&vdev, U2F_EMU_USB, SETUP_DIR);

    struct frame_header header;
    memset(&header, 0, sizeof(header));
    header.ins = U2F_VERSION;

    struct message *request = message_new_from_data(42, CMD_MSG,
            (uint8_t *)&header, sizeof(header));

    /* When */
    bool ret = usb_send_request(vdev, request);

    /* Then */
    EXPECT_TRUE(ret);
    EXPECT_TRUE(u2f_emu_vdev_has_response(vdev));

    /* After */
    message_free(request);
    u2f_emu_vdev_free(vdev);
}

TEST(VersionIn, USB)
{
    /* Given */
    u2f_emu_vdev *vdev = NULL;
    u2f_emu_vdev_new(&vdev, U2F_EMU_USB, SETUP_DIR);

    struct frame_header header;
    memset(&header, 0, sizeof(header));
    header.ins = U2F_VERSION;

    struct message *request = message_new_from_data(42, CMD_MSG,
            (uint8_t *)&header, sizeof(header));

    usb_send_request(vdev, request);

    /* When */
    struct message *response = usb_recv_response(vdev);

    /* Then */
    EXPECT_NE(response, nullptr);
    EXPECT_EQ(response->payload->size, 8);
    EXPECT_FALSE(u2f_emu_vdev_has_response(vdev));
    for (int i = 0; i < strlen(VERSION_STR); ++i)
        EXPECT_EQ(response->payload->data[i], VERSION_STR[i]);
    EXPECT_EQ(response->payload->data[6], SW_NO_ERROR >> 8);
    EXPECT_EQ(response->payload->data[7], SW_NO_ERROR & 0xFF);

    /* After */
    message_free(request);
    message_free(response);
    u2f_emu_vdev_free(vdev);
}

TEST(RegisterOut, USB)
{
    /* Given */
    u2f_emu_vdev *vdev = NULL;
    u2f_emu_vdev_new(&vdev, U2F_EMU_USB, SETUP_DIR);
    uint8_t register_params[64];
    memset(register_params, 4, 64);

    struct frame_header header;
    memset(&header, 0, sizeof(header));
    header.ins = U2F_REGISTER;
    header.optional[2] = 64;

    struct message *request = message_new_from_data(42, CMD_MSG,
            (uint8_t *)&header, sizeof(header) - 1);
    message_add_data(request, register_params, 64);

    /* When */
    bool ret = usb_send_request(vdev, request);

    /* Then */
    EXPECT_TRUE(ret);
    EXPECT_TRUE(u2f_emu_vdev_has_response(vdev));

    /* After */
    message_free(request);
    u2f_emu_vdev_free(vdev);
}

TEST(RegisterIn, USB)
{
    /* Given */
    u2f_emu_vdev *vdev = NULL;
    u2f_emu_vdev_new(&vdev, U2F_EMU_USB, SETUP_DIR);
    uint8_t register_params[64];
    memset(register_params, 4, 64);

    struct frame_header header;
    memset(&header, 0, sizeof(header));
    header.ins = U2F_REGISTER;
    header.optional[2] = 64;

    struct message *request = message_new_from_data(42, CMD_MSG,
            (uint8_t *)&header, sizeof(header) - 1);
    message_add_data(request, register_params, 64);

    usb_send_request(vdev, request);

    /* When */
    struct message *response = usb_recv_response(vdev);

    /* Then */
    EXPECT_NE(response, nullptr);
    EXPECT_EQ(response->cmd, CMD_MSG);
    EXPECT_FALSE(u2f_emu_vdev_has_response(vdev));

    /* After */
    message_free(request);
    message_free(response);
    u2f_emu_vdev_free(vdev);
}


TEST(AuthOut, USB)
{
    /* Given */
    u2f_emu_vdev *vdev = NULL;
    u2f_emu_vdev_new(&vdev, U2F_EMU_USB, SETUP_DIR);
    uint8_t register_params[64];
    memset(register_params, 4, 64);

    struct frame_header reg_header;
    memset(&reg_header, 0, sizeof(reg_header));
    reg_header.ins = U2F_REGISTER;
    reg_header.optional[2] = 64;

    struct message *reg_request = message_new_from_data(42, CMD_MSG,
            (uint8_t *)&reg_header, sizeof(reg_header) - 1);
    message_add_data(reg_request, register_params, 64);

    usb_send_request(vdev, reg_request);
    struct message *reg_response = usb_recv_response(vdev);

    uint8_t key_handle_size = reg_response->payload->data[66];
    uint8_t *key_handle = (uint8_t *)malloc(key_handle_size);
    memcpy(key_handle, reg_response->payload->data + 67,
            key_handle_size);

    struct frame_header auth_header;
    memset(&auth_header, 0, sizeof(auth_header));
    auth_header.ins = U2F_AUTHENTICATE;
    auth_header.optional[2] = 64;
    auth_header.p1 = U2F_AUTH_ENFORCE;

    struct message *auth_request = message_new_from_data(42, CMD_MSG,
            (uint8_t *)&auth_header, sizeof(auth_header) - 1);
    message_add_data(auth_request, register_params, 64);
    message_add_data(auth_request, &key_handle_size, 1);
    message_add_data(auth_request, key_handle, key_handle_size);

    /* When */
    bool ret = usb_send_request(vdev, auth_request);

    /* Then */
    EXPECT_TRUE(ret);
    EXPECT_TRUE(u2f_emu_vdev_has_response(vdev));

    /* After */
    free(key_handle);
    message_free(reg_request);
    message_free(auth_request);
    message_free(reg_response);
    u2f_emu_vdev_free(vdev);
}

TEST(AuthIn, USB)
{
    /* Given */
    u2f_emu_vdev *vdev = NULL;
    u2f_emu_vdev_new(&vdev, U2F_EMU_USB, SETUP_DIR);
    uint8_t register_params[64];
    memset(register_params, 4, 64);

    struct frame_header reg_header;
    memset(&reg_header, 0, sizeof(reg_header));
    reg_header.ins = U2F_REGISTER;
    reg_header.optional[2] = 64;

    struct message *reg_request = message_new_from_data(42, CMD_MSG,
            (uint8_t *)&reg_header, sizeof(reg_header) - 1);
    message_add_data(reg_request, register_params, 64);

    usb_send_request(vdev, reg_request);
    struct message *reg_response = usb_recv_response(vdev);

    uint8_t key_handle_size = reg_response->payload->data[66];
    uint8_t *key_handle = (uint8_t *)malloc(key_handle_size);
    memcpy(key_handle, reg_response->payload->data + 67,
            key_handle_size);

    struct frame_header auth_header;
    memset(&auth_header, 0, sizeof(auth_header));
    auth_header.ins = U2F_AUTHENTICATE;
    auth_header.optional[2] = 64;
    auth_header.p1 = U2F_AUTH_ENFORCE;

    struct message *auth_request = message_new_from_data(42, CMD_MSG,
            (uint8_t *)&auth_header, sizeof(auth_header) - 1);
    message_add_data(auth_request, register_params, 64);
    message_add_data(auth_request, &key_handle_size, 1);
    message_add_data(auth_request, key_handle, key_handle_size);
    usb_send_request(vdev, auth_request);

    /* When */
    struct message *auth_response = usb_recv_response(vdev);

    /* Then */
    EXPECT_NE(auth_response, nullptr);
    EXPECT_EQ(auth_response->cmd, CMD_MSG);
    EXPECT_FALSE(u2f_emu_vdev_has_response(vdev));

    /* After */
    free(key_handle);
    message_free(reg_request);
    message_free(auth_request);
    message_free(reg_response);
    u2f_emu_vdev_free(vdev);
}

TEST(AuthInCheck, USB)
{
    /* Given */
    u2f_emu_vdev *vdev = NULL;
    u2f_emu_vdev_new(&vdev, U2F_EMU_USB, SETUP_DIR);
    uint8_t register_params[64];
    memset(register_params, 4, 64);

    struct frame_header reg_header;
    memset(&reg_header, 0, sizeof(reg_header));
    reg_header.ins = U2F_REGISTER;
    reg_header.optional[2] = 64;

    struct message *reg_request = message_new_from_data(42, CMD_MSG,
            (uint8_t *)&reg_header, sizeof(reg_header) - 1);
    message_add_data(reg_request, register_params, 64);

    usb_send_request(vdev, reg_request);
    struct message *reg_response = usb_recv_response(vdev);

    uint8_t key_handle_size = reg_response->payload->data[66];
    uint8_t *key_handle = (uint8_t *)malloc(key_handle_size);
    memcpy(key_handle, reg_response->payload->data + 67,
            key_handle_size);

    struct frame_header auth_header;
    memset(&auth_header, 0, sizeof(auth_header));
    auth_header.ins = U2F_AUTHENTICATE;
    auth_header.optional[2] = 64;
    auth_header.p1 = U2F_AUTH_CHECK;

    struct message *auth_request = message_new_from_data(42, CMD_MSG,
            (uint8_t *)&auth_header, sizeof(auth_header) - 1);
    message_add_data(auth_request, register_params, 64);
    message_add_data(auth_request, &key_handle_size, 1);
    message_add_data(auth_request, key_handle, key_handle_size);
    usb_send_request(vdev, auth_request);

    /* When */
    struct message *auth_response = usb_recv_response(vdev);

    /* Then */
    EXPECT_NE(auth_response, nullptr);
    EXPECT_EQ(auth_response->cmd, CMD_MSG);
    EXPECT_FALSE(u2f_emu_vdev_has_response(vdev));

    /* After */
    free(key_handle);
    message_free(reg_request);
    message_free(auth_request);
    message_free(reg_response);
    u2f_emu_vdev_free(vdev);
}