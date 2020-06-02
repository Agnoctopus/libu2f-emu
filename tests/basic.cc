#include <gtest/gtest.h>

extern "C" {
    #include "u2f-emu.h"
}


#define SETUP_DIR ".u2f.tmp"


TEST(USB, BasicNew)
{
    /* Given */
    u2f_emu_vdev *vdev = NULL;

    /* When */
    u2f_emu_rc rc = u2f_emu_vdev_new(&vdev, U2F_EMU_USB, SETUP_DIR);

    /* Then */
    EXPECT_EQ(rc, U2F_EMU_OK);
    EXPECT_NE(vdev, nullptr);

    /* After */
    u2f_emu_vdev_free(vdev);
}

TEST(USBWrongSetupDir, BasicNew)
{
    /* Given */
    u2f_emu_vdev *vdev = NULL;

    /* When */
    u2f_emu_rc rc = u2f_emu_vdev_new(&vdev, U2F_EMU_USB, "nop");

    /* Then */
    EXPECT_EQ(rc, U2F_EMU_MEMORY_ERROR);
    EXPECT_EQ(vdev, nullptr);

    /* After */
    u2f_emu_vdev_free(vdev);
}

TEST(NFC, BasicNew)
{
    /* Given */
    u2f_emu_vdev *vdev = NULL;

    /* When */
    u2f_emu_rc rc = u2f_emu_vdev_new(&vdev, U2F_EMU_NFC, SETUP_DIR);

    /* Then */
    EXPECT_EQ(rc, U2F_EMU_SUPPORTED_ERROR);
    EXPECT_EQ(vdev, nullptr);

    /* After */
    u2f_emu_vdev_free(vdev);
}

TEST(BL, BasicNew)
{
    /* Given */
    u2f_emu_vdev *vdev = NULL;

    /* When */
    u2f_emu_rc rc = u2f_emu_vdev_new(&vdev, U2F_EMU_BLUETOOTH, SETUP_DIR);

    /* Then */
    EXPECT_EQ(rc, U2F_EMU_SUPPORTED_ERROR);
    EXPECT_EQ(vdev, nullptr);

    /* After */
    u2f_emu_vdev_free(vdev);
}

TEST(Agnostic, BasicNew)
{
    /* Given */
    u2f_emu_vdev *vdev = NULL;

    /* When */
    u2f_emu_rc rc = u2f_emu_vdev_new(&vdev, U2F_EMU_AGNOSTIC, SETUP_DIR);

    /* Then */
    EXPECT_EQ(rc, U2F_EMU_SUPPORTED_ERROR);
    EXPECT_EQ(vdev, nullptr);

    /* After */
    u2f_emu_vdev_free(vdev);
}


TEST(WrongTransport, BasicNew)
{
    /* Given */
    u2f_emu_vdev *vdev = NULL;

    /* When */
    u2f_emu_rc rc = u2f_emu_vdev_new(&vdev, (u2f_emu_transport)-1,
            SETUP_DIR);

    /* Then */
    EXPECT_EQ(rc, U2F_EMU_SUPPORTED_ERROR);
    EXPECT_EQ(vdev, nullptr);

    /* After */
    u2f_emu_vdev_free(vdev);
}

TEST(BasicUSB, BasicAPDU)
{
    /* Given */
    u2f_emu_vdev *vdev = NULL;
    u2f_emu_vdev_new(&vdev, U2F_EMU_USB, SETUP_DIR);

    /* When */
    u2f_emu_rc rc = u2f_emu_vdev_set_apdu(vdev, U2F_EMU_EXTENDED);

    /* Then */
    EXPECT_EQ(rc, U2F_EMU_PERMISSION_ERROR);

    /* After */
    u2f_emu_vdev_free(vdev);
}