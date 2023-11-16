/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "inputer_data_impl_test.h"

#include <openssl/sha.h>

#include "iam_ptr.h"
#include "inputer_data_impl.h"
#include "mock_inputer_set_data.h"
#include "scrypt.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
using namespace testing;
using namespace testing::ext;

void InputerDataImplTest::SetUpTestCase()
{
}

void InputerDataImplTest::TearDownTestCase()
{
}

void InputerDataImplTest::SetUp()
{
}

void InputerDataImplTest::TearDown()
{
}

namespace {
sptr<MockInputerSetData> GetMockInputerSetData(int32_t testAuthSubType, std::vector<uint8_t> testSetData)
{
    sptr<MockInputerSetData> mockInputerSetData(new (std::nothrow) MockInputerSetData());
    if (mockInputerSetData == nullptr) {
        return nullptr;
    }

    EXPECT_CALL(*mockInputerSetData, OnSetData(_, _))
        .Times(Exactly(1))
        .WillOnce([testAuthSubType, testSetData](int32_t authSubType, std::vector<uint8_t> data) {
            EXPECT_EQ(authSubType, testAuthSubType);
            EXPECT_THAT(data, ElementsAreArray(testSetData));
            return;
        });

    return mockInputerSetData;
}
}

HWTEST_F(InputerDataImplTest, InputerDataImplEnrollTest001, TestSize.Level0)
{
    constexpr int32_t testAuthSubType = 10000;
    constexpr uint32_t testAlgoVersion = ALGO_VERSION_V0;
    constexpr bool testIsEnroll = true;
    std::vector<uint8_t> testSalt = {1, 2, 3, 4, 5};
    std::vector<uint8_t> testData;
    std::vector<uint8_t> testSetData;

    auto mockInputerSetData = GetMockInputerSetData(testAuthSubType, testSetData);
    ASSERT_NE(mockInputerSetData, nullptr);

    InputerDataImpl inputerDataImpl(testSalt, mockInputerSetData, testAlgoVersion, testIsEnroll);
    inputerDataImpl.OnSetData(testAuthSubType, testData);
}

HWTEST_F(InputerDataImplTest, InputerDataImplEnrollTest002, TestSize.Level0)
{
    constexpr int32_t testAuthSubType = 10000;
    constexpr uint32_t testAlgoVersion = ALGO_VERSION_V0;
    constexpr bool testIsEnroll = true;
    std::vector<uint8_t> testSalt = {2, 3, 4, 5, 6, 7};
    std::vector<uint8_t> testData = {1, 2, 3, 4, 5, 6};

    Scrypt scrypt(testSalt);
    std::vector<uint8_t> testSetData = scrypt.GetScrypt(testData, testAlgoVersion);

    auto mockInputerSetData = GetMockInputerSetData(testAuthSubType, testSetData);
    ASSERT_NE(mockInputerSetData, nullptr);

    InputerDataImpl inputerDataImpl(testSalt, mockInputerSetData, testAlgoVersion, testIsEnroll);
    inputerDataImpl.OnSetData(testAuthSubType, testData);
}

HWTEST_F(InputerDataImplTest, InputerDataImplEnrollTest003, TestSize.Level0)
{
    constexpr int32_t testAuthSubType = 10000;
    constexpr uint32_t testAlgoVersion = ALGO_VERSION_V1;
    constexpr bool testIsEnroll = true;
    std::vector<uint8_t> testSalt = {3, 4, 5, 6, 7, 8};
    std::vector<uint8_t> testData = {2, 3, 4, 5, 6, 7};

    Scrypt scrypt(testSalt);
    std::vector<uint8_t> testSetData = scrypt.GetScrypt(testData, testAlgoVersion);

    auto mockInputerSetData = GetMockInputerSetData(testAuthSubType, testSetData);
    ASSERT_NE(mockInputerSetData, nullptr);

    InputerDataImpl inputerDataImpl(testSalt, mockInputerSetData, testAlgoVersion, testIsEnroll);
    inputerDataImpl.OnSetData(testAuthSubType, testData);
}

HWTEST_F(InputerDataImplTest, InputerDataImplEnrollTest004, TestSize.Level0)
{
    constexpr int32_t testAuthSubType = 10000;
    constexpr uint32_t testAlgoVersion = ALGO_VERSION_V2;
    constexpr bool testIsEnroll = true;
    std::vector<uint8_t> testSalt = {4, 5, 6, 7, 8, 9};
    std::vector<uint8_t> testData = {3, 4, 5, 6, 7, 8};

    Scrypt scrypt(testSalt);
    std::vector<uint8_t> testSetData = scrypt.GetScrypt(testData, testAlgoVersion);

    uint8_t sha256Result[SHA256_DIGEST_LENGTH] = {};
    EXPECT_EQ(SHA256(testData.data(), testData.size(), sha256Result), sha256Result);
    testSetData.insert(testSetData.end(), sha256Result, sha256Result + SHA256_DIGEST_LENGTH);

    auto mockInputerSetData = GetMockInputerSetData(testAuthSubType, testSetData);
    ASSERT_NE(mockInputerSetData, nullptr);

    InputerDataImpl inputerDataImpl(testSalt, mockInputerSetData, testAlgoVersion, testIsEnroll);
    inputerDataImpl.OnSetData(testAuthSubType, testData);
}

HWTEST_F(InputerDataImplTest, InputerDataImplAuthTest001, TestSize.Level0)
{
    constexpr int32_t testAuthSubType = 10000;
    constexpr uint32_t testAlgoVersion = ALGO_VERSION_V0;
    constexpr bool testIsEnroll = false;
    std::vector<uint8_t> testSalt;
    std::vector<uint8_t> testData;
    std::vector<uint8_t> testSetData;

    auto mockInputerSetData = GetMockInputerSetData(testAuthSubType, testSetData);
    ASSERT_NE(mockInputerSetData, nullptr);

    InputerDataImpl inputerDataImpl(testSalt, mockInputerSetData, testAlgoVersion, testIsEnroll);
    inputerDataImpl.OnSetData(testAuthSubType, testData);
}

HWTEST_F(InputerDataImplTest, InputerDataImplAuthTest002, TestSize.Level0)
{
    constexpr int32_t testAuthSubType = 10000;
    constexpr uint32_t testAlgoVersion = ALGO_VERSION_V0;
    constexpr bool testIsEnroll = false;
    std::vector<uint8_t> testSalt = {5, 6, 7, 8, 9, 10};
    std::vector<uint8_t> testData = {5, 6, 7, 8, 9, 10};

    Scrypt scrypt(testSalt);
    std::vector<uint8_t> testSetData = scrypt.GetScrypt(testData, testAlgoVersion);

    auto mockInputerSetData = GetMockInputerSetData(testAuthSubType, testSetData);
    ASSERT_NE(mockInputerSetData, nullptr);

    InputerDataImpl inputerDataImpl(testSalt, mockInputerSetData, testAlgoVersion, testIsEnroll);
    inputerDataImpl.OnSetData(testAuthSubType, testData);
}

HWTEST_F(InputerDataImplTest, InputerDataImplAuthTest003, TestSize.Level0)
{
    constexpr int32_t testAuthSubType = 10000;
    constexpr uint32_t testAlgoVersion = ALGO_VERSION_V1;
    constexpr bool testIsEnroll = false;
    std::vector<uint8_t> testSalt = {6, 7, 8, 9, 10, 11};
    std::vector<uint8_t> testData = {6, 7, 8, 9, 10, 11};

    Scrypt scrypt(testSalt);
    std::vector<uint8_t> testSetData = scrypt.GetScrypt(testData, testAlgoVersion);

    auto mockInputerSetData = GetMockInputerSetData(testAuthSubType, testSetData);
    ASSERT_NE(mockInputerSetData, nullptr);

    InputerDataImpl inputerDataImpl(testSalt, mockInputerSetData, testAlgoVersion, testIsEnroll);
    inputerDataImpl.OnSetData(testAuthSubType, testData);
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
