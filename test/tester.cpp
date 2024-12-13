#include <gtest/gtest.h>

#include "daemon.h"

TEST(DaemonTest, InvalidCharacterTest) {
    ASSERT_EQ(contains_invalid_characters("abcdef"), 0);
}
