/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#define private public
#include "inputer_data_impl.h"
#include "inputer_data_impl_test.h"

#include <openssl/sha.h>

#include "iam_ptr.h"
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
sptr<MockInputerSetData> GetMockInputerSetData(int32_t testAuthSubType,
    std::vector<uint8_t> testSetData, int32_t testErrorCode)
{
    sptr<MockInputerSetData> mockInputerSetData(new (std::nothrow) MockInputerSetData());
    if (mockInputerSetData == nullptr) {
        return nullptr;
    }

    EXPECT_CALL(*mockInputerSetData, OnSetData(_, _, _))
        .Times(Exactly(1))
        .WillOnce([testAuthSubType, testSetData, testErrorCode](int32_t authSubType,
            std::vector<uint8_t> data, int32_t errorCode) {
            EXPECT_EQ(authSubType, testAuthSubType);
            EXPECT_THAT(data, ElementsAreArray(testSetData));
            EXPECT_EQ(errorCode, testErrorCode);
            return;
        });

    return mockInputerSetData;
}
}

HWTEST_F(InputerDataImplTest, CheckPinComplexity001, TestSize.Level0)
{
    constexpr int32_t testAuthSubType = 10000;
    constexpr uint32_t testAlgoVersion = ALGO_VERSION_V2;
    std::vector<uint8_t> testSalt = {1, 2, 3, 4, 5};
    constexpr GetDataMode testMode = GET_DATA_MODE_NONE;
    #define CUSTOMIZATION_ENTERPRISE_DEVICE_MANAGEMENT_ENABLE
    InputerDataImpl inputerDataImpl(testMode, testAlgoVersion, testSalt, nullptr);
    int32_t result = inputerDataImpl.CheckPinComplexity(testAuthSubType, testSalt);
    EXPECT_EQ(result, UserAuth::COMPLEXITY_CHECK_FAILED);
}

HWTEST_F(InputerDataImplTest, CheckPinComplexity002, TestSize.Level0)
{
    constexpr int32_t testAuthSubType = 10000;
    constexpr uint32_t testAlgoVersion = ALGO_VERSION_V2;
    std::vector<uint8_t> testSalt = {1, 2, 3, 4, 5};
    constexpr GetDataMode testMode = GET_DATA_MODE_NONE;
    #define CUSTOMIZATION_ENTERPRISE_DEVICE_MANAGEMENT_ENABLE
    InputerDataImpl inputerDataImpl(testMode, testAlgoVersion, testSalt, nullptr);
    int32_t result = inputerDataImpl.CheckPinComplexity(testAuthSubType, testSalt);
    EXPECT_EQ(result, UserAuth::COMPLEXITY_CHECK_FAILED);
}

HWTEST_F(InputerDataImplTest, OnSetDataInner001, TestSize.Level0)
{
    constexpr int32_t testAuthSubType = 10000;
    constexpr uint32_t testAlgoVersion = ALGO_VERSION_V2;
    constexpr GetDataMode testMode = GET_DATA_MODE_NONE;
    std::vector<uint8_t> testSalt = {1, 2, 3, 4, 5};
    std::vector<uint8_t> testSetData;
    constexpr int32_t testErrorCode = 14;
    InputerDataImpl inputerDataImpl(testMode, testAlgoVersion, testSalt, nullptr);
    EXPECT_NO_THROW(inputerDataImpl.OnSetDataInner(testAuthSubType, testSetData, testErrorCode));
}

HWTEST_F(InputerDataImplTest, GetPinDataTest001, TestSize.Level0)
{
    constexpr int32_t testAuthSubType = 10000;
    constexpr uint32_t testAlgoVersion = ALGO_VERSION_V2;
    constexpr GetDataMode testMode = GET_DATA_MODE_NONE;
    std::vector<uint8_t> testSalt = {1, 2, 3, 4, 5};
    std::vector<uint8_t> testData = {6, 7};
    std::vector<uint8_t> testSetData;
    int32_t testErrorCode = 14;

    auto mockInputerSetData = GetMockInputerSetData(testAuthSubType, testSetData, testErrorCode);
    ASSERT_NE(mockInputerSetData, nullptr);

    InputerDataImpl inputerDataImpl(testMode, testAlgoVersion, testSalt, mockInputerSetData);
    EXPECT_NO_THROW(inputerDataImpl.GetPinData(testAuthSubType, testData, testSetData, testErrorCode));
}

HWTEST_F(InputerDataImplTest, GetPinDataTest002, TestSize.Level0)
{
    constexpr int32_t testAuthSubType = 10000;
    constexpr uint32_t testAlgoVersion = ALGO_VERSION_V2;
    constexpr GetDataMode testMode = GET_DATA_MODE_ALL_IN_ONE_ENROLL;
    std::vector<uint8_t> testSalt = {1, 2, 3, 4, 5};
    std::vector<uint8_t> testData = {1, 2, 3, 4, 6};
    std::vector<uint8_t> testSetData;
    int32_t testErrorCode = 14;

    auto mockInputerSetData = GetMockInputerSetData(testAuthSubType, testSetData, testErrorCode);
    ASSERT_NE(mockInputerSetData, nullptr);

    InputerDataImpl inputerDataImpl(testMode, testAlgoVersion, testSalt, mockInputerSetData);
    EXPECT_NO_THROW(inputerDataImpl.GetPinData(testAuthSubType, testData, testSetData, testErrorCode));
}

HWTEST_F(InputerDataImplTest, InputerDataImplEnrollTest001, TestSize.Level0)
{
    constexpr int32_t testAuthSubType = 10000;
    constexpr uint32_t testAlgoVersion = ALGO_VERSION_V0;
    constexpr GetDataMode testMode = GET_DATA_MODE_ALL_IN_ONE_ENROLL;
    std::vector<uint8_t> testSalt = {1, 2, 3, 4, 5};
    std::vector<uint8_t> testData;
    std::vector<uint8_t> testSetData;
    int32_t testErrorCode = 14;

    auto mockInputerSetData = GetMockInputerSetData(testAuthSubType, testSetData, testErrorCode);
    ASSERT_NE(mockInputerSetData, nullptr);

    InputerDataImpl inputerDataImpl(testMode, testAlgoVersion, testSalt, mockInputerSetData);
    inputerDataImpl.OnSetData(testAuthSubType, testData);
}

HWTEST_F(InputerDataImplTest, InputerDataImplEnrollTest002, TestSize.Level0)
{
    constexpr int32_t testAuthSubType = 10000;
    constexpr uint32_t testAlgoVersion = ALGO_VERSION_V0;
    constexpr GetDataMode testMode = GET_DATA_MODE_ALL_IN_ONE_ENROLL;
    std::vector<uint8_t> testSalt = {2, 3, 4, 5, 6, 7};
    std::vector<uint8_t> testData = {1, 2, 3, 4, 5, 6};
    constexpr int32_t testErrorCode = 0;

    Scrypt scrypt(testSalt);
    std::vector<uint8_t> testSetData = scrypt.GetScrypt(testData, testAlgoVersion);

    auto mockInputerSetData = GetMockInputerSetData(testAuthSubType, testSetData, testErrorCode);
    ASSERT_NE(mockInputerSetData, nullptr);

    InputerDataImpl inputerDataImpl(testMode, testAlgoVersion, testSalt, mockInputerSetData);
    inputerDataImpl.OnSetData(testAuthSubType, testData);
}

HWTEST_F(InputerDataImplTest, InputerDataImplEnrollTest003, TestSize.Level0)
{
    constexpr int32_t testAuthSubType = 10000;
    constexpr uint32_t testAlgoVersion = ALGO_VERSION_V1;
    constexpr GetDataMode testMode = GET_DATA_MODE_ALL_IN_ONE_ENROLL;
    std::vector<uint8_t> testSalt = {3, 4, 5, 6, 7, 8};
    std::vector<uint8_t> testData = {2, 3, 4, 5, 6, 7};
    constexpr int32_t testErrorCode = 0;

    Scrypt scrypt(testSalt);
    std::vector<uint8_t> testSetData = scrypt.GetScrypt(testData, testAlgoVersion);

    auto mockInputerSetData = GetMockInputerSetData(testAuthSubType, testSetData, testErrorCode);
    ASSERT_NE(mockInputerSetData, nullptr);

    InputerDataImpl inputerDataImpl(testMode, testAlgoVersion, testSalt, mockInputerSetData);
    inputerDataImpl.OnSetData(testAuthSubType, testData);
}

HWTEST_F(InputerDataImplTest, InputerDataImplEnrollTest004, TestSize.Level0)
{
    constexpr int32_t testAuthSubType = 10000;
    constexpr uint32_t testAlgoVersion = ALGO_VERSION_V2;
    constexpr GetDataMode testMode = GET_DATA_MODE_ALL_IN_ONE_ENROLL;
    std::vector<uint8_t> testSalt = {4, 5, 6, 7, 8, 9};
    std::vector<uint8_t> testData = {3, 4, 5, 6, 7, 8};
    constexpr int32_t testErrorCode = 0;

    Scrypt scrypt(testSalt);
    std::vector<uint8_t> testSetData = scrypt.GetScrypt(testData, testAlgoVersion);

    uint8_t sha256Result[SHA256_DIGEST_LENGTH] = {};
    EXPECT_EQ(SHA256(testData.data(), testData.size(), sha256Result), sha256Result);
    testSetData.insert(testSetData.end(), sha256Result, sha256Result + SHA256_DIGEST_LENGTH);

    auto mockInputerSetData = GetMockInputerSetData(testAuthSubType, testSetData, testErrorCode);
    ASSERT_NE(mockInputerSetData, nullptr);

    InputerDataImpl inputerDataImpl(testMode, testAlgoVersion, testSalt, mockInputerSetData);
    inputerDataImpl.OnSetData(testAuthSubType, testData);
}

HWTEST_F(InputerDataImplTest, InputerDataImplAuthTest001, TestSize.Level0)
{
    constexpr int32_t testAuthSubType = 10000;
    constexpr uint32_t testAlgoVersion = ALGO_VERSION_V0;
    constexpr GetDataMode testMode = GET_DATA_MODE_ALL_IN_ONE_AUTH;
    std::vector<uint8_t> testSalt;
    std::vector<uint8_t> testData;
    std::vector<uint8_t> testSetData;
    constexpr int32_t testErrorCode = 14;

    auto mockInputerSetData = GetMockInputerSetData(testAuthSubType, testSetData, testErrorCode);
    ASSERT_NE(mockInputerSetData, nullptr);

    InputerDataImpl inputerDataImpl(testMode, testAlgoVersion, testSalt, mockInputerSetData);
    inputerDataImpl.OnSetData(testAuthSubType, testData);
}

HWTEST_F(InputerDataImplTest, InputerDataImplAuthTest002, TestSize.Level0)
{
    constexpr int32_t testAuthSubType = 10000;
    constexpr uint32_t testAlgoVersion = ALGO_VERSION_V0;
    constexpr GetDataMode testMode = GET_DATA_MODE_ALL_IN_ONE_AUTH;
    std::vector<uint8_t> testSalt = {5, 6, 7, 8, 9, 10};
    std::vector<uint8_t> testData = {5, 6, 7, 8, 9, 10};
    constexpr int32_t testErrorCode = 0;

    Scrypt scrypt(testSalt);
    std::vector<uint8_t> testSetData = scrypt.GetScrypt(testData, testAlgoVersion);

    auto mockInputerSetData = GetMockInputerSetData(testAuthSubType, testSetData, testErrorCode);
    ASSERT_NE(mockInputerSetData, nullptr);

    InputerDataImpl inputerDataImpl(testMode, testAlgoVersion, testSalt, mockInputerSetData);
    inputerDataImpl.OnSetData(testAuthSubType, testData);
}

HWTEST_F(InputerDataImplTest, InputerDataImplAuthTest003, TestSize.Level0)
{
    constexpr int32_t testAuthSubType = 10000;
    constexpr uint32_t testAlgoVersion = ALGO_VERSION_V1;
    constexpr GetDataMode testMode = GET_DATA_MODE_ALL_IN_ONE_AUTH;
    std::vector<uint8_t> testSalt = {6, 7, 8, 9, 10, 11};
    std::vector<uint8_t> testData = {6, 7, 8, 9, 10, 11};
    constexpr int32_t testErrorCode = 0;

    Scrypt scrypt(testSalt);
    std::vector<uint8_t> testSetData = scrypt.GetScrypt(testData, testAlgoVersion);

    auto mockInputerSetData = GetMockInputerSetData(testAuthSubType, testSetData, testErrorCode);
    ASSERT_NE(mockInputerSetData, nullptr);

    InputerDataImpl inputerDataImpl(testMode, testAlgoVersion, testSalt, mockInputerSetData);
    inputerDataImpl.OnSetData(testAuthSubType, testData);
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
