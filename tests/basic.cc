#include <gtest/gtest.h>

extern "C" {
    #include "u2f-emu.h"
}


#define SETUP_DIR ".u2f.tmp"


TEST(SetupDir, BasicNew)
{
    /* Given */
    u2f_emu_vdev *vdev = NULL;

    /* When */
    u2f_emu_rc rc = u2f_emu_vdev_new_from_dir(&vdev, SETUP_DIR);

    /* Then */
    EXPECT_EQ(rc, U2F_EMU_OK);
    EXPECT_NE(vdev, nullptr);

    /* After */
    u2f_emu_vdev_free(vdev);
}

TEST(WrongSetupDir, BasicNew)
{
    /* Given */
    u2f_emu_vdev *vdev = NULL;

    /* When */
    u2f_emu_rc rc = u2f_emu_vdev_new_from_dir(&vdev, "nop");

    /* Then */
    EXPECT_EQ(rc, U2F_EMU_MEMORY_ERROR);
    EXPECT_EQ(vdev, nullptr);

    /* After */
    u2f_emu_vdev_free(vdev);
}