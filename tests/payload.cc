#include <cstring>
#include <cstdbool>
#include <cstdint>
#include <gtest/gtest.h>

extern "C" {
    #include "payload.h"
}


TEST(PayloadNew, Payload)
{
    /* Given */
    struct payload *payload = NULL;

    /* When */
    payload = payload_new();

    /* Then */
    EXPECT_NE(payload, nullptr);
    EXPECT_NE(payload->data, nullptr);
    EXPECT_EQ(payload->size, 0);

    /* After */
    payload_free(payload);
}

TEST(PayloadNewCap, Payload)
{
    /* Given */
    struct payload *payload = NULL;

    /* When */
    payload = payload_new_with_capacity(4000);

    /* Then */
    EXPECT_NE(payload, nullptr);
    EXPECT_NE(payload->data, nullptr);
    EXPECT_EQ(payload->size, 0);
    EXPECT_EQ(payload->capacity, 4096);

    /* After */
    payload_free(payload);
}

TEST(PayloadData, Payload)
{
    /* Given */
    struct payload *payload = NULL;
    char data[42];
    memset(data, 4, 42);

    /* When */
    payload = payload_new_from_data((uint8_t *)data, 42);

    /* Then */
    EXPECT_NE(payload, nullptr);
    EXPECT_NE(payload->data, nullptr);
    EXPECT_EQ(payload->size, 42);
    for (int i = 0; i < 42; ++i)
        EXPECT_EQ(payload->data[i], 4);

    /* After */
    payload_free(payload);
}


TEST(PayloadAddData, Payload)
{
    /* Given */
    struct payload *payload = payload_new();
    char data[42];
    memset(data, 4, 42);

    /* When */
    bool ret = payload_add_data(payload, (uint8_t *)data, 42);

    /* Then */
    EXPECT_TRUE(ret);
    EXPECT_NE(payload, nullptr);
    EXPECT_NE(payload->data, nullptr);
    EXPECT_EQ(payload->size, 42);
    for (int i = 0; i < 42; ++i)
        EXPECT_EQ(payload->data[i], 4);

    /* After */
    payload_free(payload);
}


TEST(PayloadAddDataOverflow, Payload)
{
    /* Given */
    struct payload *payload = payload_new();
    char data[42];

    /* When */
    bool ret = payload_new_from_data((uint8_t *)data, 1 << 17);

    /* Then */
    EXPECT_FALSE(ret);

    /* After */
    payload_free(payload);
}
