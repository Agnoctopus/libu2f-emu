#include <gtest/gtest.h>

extern "C" {
    #include "u2f-emu.h"
}


#define SETUP_DIR ".u2f.tmp"

TEST(SanityCheck, Sanity) {
    u2f_emu_vdev *vdev = NULL;
    u2f_emu_rc rc =  u2f_emu_vdev_new(&vdev, U2F_EMU_USB, SETUP_DIR);

    EXPECT_EQ(rc, U2F_EMU_OK);
    EXPECT_NE(vdev, nullptr);
}
