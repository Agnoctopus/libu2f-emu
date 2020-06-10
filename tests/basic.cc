#include <gtest/gtest.h>

extern "C" {
    #include "u2f-emu.h"
}


#define SETUP_DIR ".u2f.tmp"


TEST(SetupDir, Basic)
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

TEST(WrongSetupDir, Basic)
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

TEST(Ephemeral, Basic)
{
    /* Given */
    u2f_emu_vdev *vdev = NULL;

    /* When */
    u2f_emu_rc rc = u2f_emu_vdev_new_ephemeral(&vdev);

    /* Then */
    EXPECT_EQ(rc, U2F_EMU_OK);
    EXPECT_NE(vdev, nullptr);

    /* After */
    u2f_emu_vdev_free(vdev);
}

/**
** \brief Basic counter representation.
*/
struct counter
{
    /* Virtual device counter */
    struct u2f_emu_vdev_counter vdev_counter;

    /* Private attributes */
    uint32_t value; /**< Value of the counter */
};

/**
** \brief Increment the counter of an U2F virtual device.
**
** \param vdev_counter The virtual device counter to increment.
*/
static void counter_increment(
        struct u2f_emu_vdev_counter *vdev_counter)
{
    /* Get counter */
    struct counter *counter = (struct counter *)vdev_counter;

    /* Increment counter */
    ++counter->value;
}

/**
** \brief Read the counter value of an U2F virtual device.
**
** \param vdev_counter The virtual device counter to read.
** \return The counter value.
*/
static uint32_t counter_read(
        struct u2f_emu_vdev_counter *vdev_counter)
{
    /* Get counter */
    struct counter *counter = (struct counter *)vdev_counter;
    return counter->value;
}

TEST(Normal, Basic)
{
    /* Given */
    u2f_emu_vdev *vdev = NULL;
    char cert_pem[] =
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBgzCCASmgAwIBAgIUFVUMHIHW4knP52q7AytPlg7SEGUwCgYIKoZIzj0EAwIw\n"
        "FzEVMBMGA1UEAwwMVTJGIGVtdWxhdGVkMB4XDTIwMDYxMDEyMzU1NFoXDTI0MDYw\n"
        "OTEyMzU1NFowFzEVMBMGA1UEAwwMVTJGIGVtdWxhdGVkMFkwEwYHKoZIzj0CAQYI\n"
        "KoZIzj0DAQcDQgAEyCDbssek9NoYXR1BqM6MyuNxWrxlDgFn4PcK6KDLQLDtHTxM\n"
        "phEN0Ezvk+dbExYMMk7bLiDX9AYEco6z3/IbyKNTMFEwHQYDVR0OBBYEFPRzDoYL\n"
        "0kW9wG/O40+GVW/VT7x9MB8GA1UdIwQYMBaAFPRzDoYL0kW9wG/O40+GVW/VT7x9\n"
        "MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAOYBady3ImdxE7F2\n"
        "fmDb6bXcsz37NROpW/np26fqqZ27AiAnCZZ0jFIZrCvjJ0mTM2ZxM0J4htTN2QRO\n"
        "byPcDAlW5A==\n"
        "-----END CERTIFICATE-----\n";
    char privkey_pem[] =
        "-----BEGIN EC PRIVATE KEY-----\n"
        "MHcCAQEEIPrY0FtZh1+ybWraaHs1wazd2SmraryCkE00fgyUVHqCoAoGCCqGSM49\n"
        "AwEHoUQDQgAEyCDbssek9NoYXR1BqM6MyuNxWrxlDgFn4PcK6KDLQLDtHTxMphEN\n"
        "0Ezvk+dbExYMMk7bLiDX9AYEco6z3/IbyA==\n"
        "-----END EC PRIVATE KEY-----\n";
    struct counter counter;
    counter.vdev_counter.counter_increment = counter_increment;
    counter.vdev_counter.counter_read = counter_read;
    counter.value = 42;
    struct u2f_emu_vdev_setup setup;
    setup.certificate = cert_pem;
    setup.private_key = privkey_pem;
    setup.counter = (u2f_emu_vdev_counter *)&counter;


    /* When */
    u2f_emu_rc rc = u2f_emu_vdev_new(&vdev, &setup);

    /* Then */
    EXPECT_EQ(rc, U2F_EMU_OK);
    EXPECT_NE(vdev, nullptr);

    /* After */
    u2f_emu_vdev_free(vdev);
}