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
    return mockInputerSetData;
}
}

HWTEST_F(InputerDataImplTest, CheckPinComplexity001, TestSize.Level1)
{
    InputerGetDataParam param = {};
    param.algoVersion = PIN_ALGO_VERSION_V2;
    param.algoParameter = {1, 2, 3, 4, 5};
    param.mode = GET_DATA_MODE_NONE;
    constexpr int32_t testAuthSubType = 10000;
    #define CUSTOMIZATION_ENTERPRISE_DEVICE_MANAGEMENT_ENABLE
    InputerDataImpl inputerDataImpl(param);
    std::vector<uint8_t> testSalt = {1, 2, 3, 4, 5, 6};
    int32_t result = inputerDataImpl.CheckPinComplexity(testAuthSubType, testSalt);
    EXPECT_EQ(result, 0);
}

HWTEST_F(InputerDataImplTest, CheckPinComplexity002, TestSize.Level1)
{
    constexpr int32_t testAuthSubType = 10000;
    InputerGetDataParam param = {};
    param.algoVersion = PIN_ALGO_VERSION_V2;
    param.algoParameter = {1, 2, 3, 4, 5};
    param.mode = GET_DATA_MODE_NONE;
    #define CUSTOMIZATION_ENTERPRISE_DEVICE_MANAGEMENT_ENABLE
    InputerDataImpl inputerDataImpl(param);
    std::vector<uint8_t> testSalt = {1, 2, 3, 4, 5, 6};
    int32_t result = inputerDataImpl.CheckPinComplexity(testAuthSubType, testSalt);
    EXPECT_EQ(result, 0);
}

HWTEST_F(InputerDataImplTest, OnSetDataInner001, TestSize.Level1)
{
    constexpr int32_t testAuthSubType = 10000;
    InputerGetDataParam param = {};
    param.algoVersion = PIN_ALGO_VERSION_V2;
    param.algoParameter = {1, 2, 3, 4, 5};
    param.mode = GET_DATA_MODE_NONE;
    std::vector<uint8_t> testSetData;
    constexpr int32_t testErrorCode = 14;
    InputerDataImpl inputerDataImpl(param);
    EXPECT_NO_THROW(inputerDataImpl.OnSetDataInner(testAuthSubType, testSetData, testErrorCode));
}

HWTEST_F(InputerDataImplTest, GetRecoveryKeyDataTest001, TestSize.Level1)
{
    constexpr int32_t testAuthSubType = 10000;
    std::vector<uint8_t> testData = {6, 7};
    std::vector<uint8_t> testSetData;
    InputerGetDataParam param = {};
    param.algoVersion = RECOVERY_KEY_ALGO_VERSION_V0;
    param.algoParameter = {1, 2, 3, 4, 5};
    param.mode = GET_DATA_MODE_NONE;
    int32_t testErrorCode = 1;
    param.inputerSetData = GetMockInputerSetData(testAuthSubType, testSetData, testErrorCode);
    ASSERT_NE(param.inputerSetData, nullptr);

    InputerDataImpl inputerDataImpl(param);
    EXPECT_NO_THROW(inputerDataImpl.GetRecoveryKeyData(testData, testSetData, testErrorCode));

    param.algoVersion = PIN_ALGO_VERSION_V2;
    InputerDataImpl inputerDataImpl1(param);
    EXPECT_NO_THROW(inputerDataImpl1.GetRecoveryKeyData(testData, testSetData, testErrorCode));
}


HWTEST_F(InputerDataImplTest, GetPinDataTest001, TestSize.Level1)
{
    InputerGetDataParam param = {};
    param.mode = GET_DATA_MODE_NONE;
    param.algoVersion = PIN_ALGO_VERSION_V2;
    param.authSubType = 10000;
    param.algoParameter = {1, 2, 3, 4, 5};

    std::vector<uint8_t> testData = {6, 7};
    std::vector<uint8_t> testSetData;
    int32_t testErrorCode = 14;

    auto mockInputerSetData = GetMockInputerSetData(param.authSubType, testSetData, testErrorCode);
    ASSERT_NE(mockInputerSetData, nullptr);

    InputerDataImpl inputerDataImpl(param);
    EXPECT_NO_THROW(inputerDataImpl.GetPinData(param.authSubType, testData, testSetData, testErrorCode));
}

HWTEST_F(InputerDataImplTest, GetPinDataTest002, TestSize.Level1)
{
    constexpr int32_t testAuthSubType = 10000;
    InputerGetDataParam param = {};
    param.algoVersion = PIN_ALGO_VERSION_V2;
    param.algoParameter = {1, 2, 3, 4, 5};
    param.mode = GET_DATA_MODE_ALL_IN_ONE_PIN_ENROLL;
    std::vector<uint8_t> testData = {1, 2, 3, 4, 6};
    std::vector<uint8_t> testSetData;
    int32_t testErrorCode = 14;

    auto mockInputerSetData = GetMockInputerSetData(testAuthSubType, testSetData, testErrorCode);
    ASSERT_NE(mockInputerSetData, nullptr);

    InputerDataImpl inputerDataImpl(param);
    EXPECT_NO_THROW(inputerDataImpl.GetPinData(testAuthSubType, testData, testSetData, testErrorCode));
}

HWTEST_F(InputerDataImplTest, InputerDataImplEnrollTest001, TestSize.Level1)
{
    constexpr int32_t testAuthSubType = 10000;
    InputerGetDataParam param = {};
    param.algoVersion = PIN_ALGO_VERSION_V0;
    param.algoParameter = {1, 2, 3, 4, 5};
    param.mode = GET_DATA_MODE_ALL_IN_ONE_PIN_ENROLL;
    std::vector<uint8_t> testData;
    std::vector<uint8_t> testSetData;
    int32_t testErrorCode = 14;

    auto mockInputerSetData = GetMockInputerSetData(testAuthSubType, testSetData, testErrorCode);
    ASSERT_NE(mockInputerSetData, nullptr);

    InputerDataImpl inputerDataImpl(param);
    inputerDataImpl.OnSetData(testAuthSubType, testData);
}

HWTEST_F(InputerDataImplTest, InputerDataImplEnrollTest002, TestSize.Level1)
{
    constexpr int32_t testAuthSubType = 10000;
    InputerGetDataParam param = {};
    param.algoVersion = PIN_ALGO_VERSION_V0;
    param.algoParameter = {2, 3, 4, 5, 6, 7};
    param.mode = GET_DATA_MODE_ALL_IN_ONE_PIN_ENROLL;
    std::vector<uint8_t> testData = {1, 2, 3, 4, 5, 6};
    constexpr int32_t testErrorCode = 0;

    std::vector<uint8_t> testSalt = {2, 3, 4, 5, 6, 7};
    Scrypt scrypt(testSalt);
    std::vector<uint8_t> testSetData = scrypt.GetScrypt(testData, param.algoVersion);

    auto mockInputerSetData = GetMockInputerSetData(testAuthSubType, testSetData, testErrorCode);
    ASSERT_NE(mockInputerSetData, nullptr);

    InputerDataImpl inputerDataImpl(param);
    inputerDataImpl.OnSetData(testAuthSubType, testData);
}

HWTEST_F(InputerDataImplTest, InputerDataImplEnrollTest003, TestSize.Level1)
{
    constexpr int32_t testAuthSubType = 10000;
    InputerGetDataParam param = {};
    param.algoVersion = PIN_ALGO_VERSION_V1;
    param.algoParameter = {3, 4, 5, 6, 7, 8};
    param.mode = GET_DATA_MODE_ALL_IN_ONE_PIN_ENROLL;
    std::vector<uint8_t> testData = {2, 3, 4, 5, 6, 7};
    constexpr int32_t testErrorCode = 0;

    std::vector<uint8_t> testSalt = {2, 3, 4, 5, 6, 7};
    Scrypt scrypt(testSalt);
    std::vector<uint8_t> testSetData = scrypt.GetScrypt(testData, param.algoVersion);

    auto mockInputerSetData = GetMockInputerSetData(testAuthSubType, testSetData, testErrorCode);
    ASSERT_NE(mockInputerSetData, nullptr);

    InputerDataImpl inputerDataImpl(param);
    inputerDataImpl.OnSetData(testAuthSubType, testData);
}

HWTEST_F(InputerDataImplTest, InputerDataImplEnrollTest004, TestSize.Level0)
{
    constexpr int32_t testAuthSubType = 10000;
    InputerGetDataParam param = {};
    param.algoVersion = PIN_ALGO_VERSION_V2;
    param.algoParameter = {4, 5, 6, 7, 8, 9};
    param.mode = GET_DATA_MODE_ALL_IN_ONE_PIN_ENROLL;
    std::vector<uint8_t> testData = {3, 4, 5, 6, 7, 8};
    constexpr int32_t testErrorCode = 0;

    std::vector<uint8_t> testSalt = {3, 4, 5, 6, 7, 8};
    Scrypt scrypt(testSalt);
    std::vector<uint8_t> testSetData = scrypt.GetScrypt(testData, param.algoVersion);

    uint8_t sha256Result[SHA256_DIGEST_LENGTH] = {};
    EXPECT_EQ(SHA256(testData.data(), testData.size(), sha256Result), sha256Result);
    testSetData.insert(testSetData.end(), sha256Result, sha256Result + SHA256_DIGEST_LENGTH);

    auto mockInputerSetData = GetMockInputerSetData(testAuthSubType, testSetData, testErrorCode);
    ASSERT_NE(mockInputerSetData, nullptr);

    InputerDataImpl inputerDataImpl(param);
    inputerDataImpl.OnSetData(testAuthSubType, testData);
}

HWTEST_F(InputerDataImplTest, InputerDataImplAuthTest001, TestSize.Level0)
{
    constexpr int32_t testAuthSubType = 10000;
    InputerGetDataParam param = {};
    param.algoVersion = PIN_ALGO_VERSION_V0;
    param.mode = GET_DATA_MODE_ALL_IN_ONE_PIN_AUTH;
    std::vector<uint8_t> testData;
    std::vector<uint8_t> testSetData;
    constexpr int32_t testErrorCode = 14;

    auto mockInputerSetData = GetMockInputerSetData(testAuthSubType, testSetData, testErrorCode);
    ASSERT_NE(mockInputerSetData, nullptr);

    InputerDataImpl inputerDataImpl(param);
    inputerDataImpl.OnSetData(testAuthSubType, testData);
}

HWTEST_F(InputerDataImplTest, InputerDataImplAuthTest002, TestSize.Level0)
{
    constexpr int32_t testAuthSubType = 10000;
    InputerGetDataParam param = {};
    param.algoVersion = PIN_ALGO_VERSION_V0;
    param.algoParameter = {5, 6, 7, 8, 9, 10};
    param.mode = GET_DATA_MODE_ALL_IN_ONE_PIN_AUTH;
    std::vector<uint8_t> testData = {5, 6, 7, 8, 9, 10};
    constexpr int32_t testErrorCode = 0;

    std::vector<uint8_t> testSalt = {5, 6, 7, 8, 9, 10};
    Scrypt scrypt(testSalt);
    std::vector<uint8_t> testSetData = scrypt.GetScrypt(testData, param.algoVersion);

    auto mockInputerSetData = GetMockInputerSetData(testAuthSubType, testSetData, testErrorCode);
    ASSERT_NE(mockInputerSetData, nullptr);

    InputerDataImpl inputerDataImpl(param);
    inputerDataImpl.OnSetData(testAuthSubType, testData);
}

HWTEST_F(InputerDataImplTest, InputerDataImplAuthTest003, TestSize.Level0)
{
    constexpr int32_t testAuthSubType = 10000;
    InputerGetDataParam param = {};
    param.algoVersion = PIN_ALGO_VERSION_V1;
    param.algoParameter = {6, 7, 8, 9, 10, 11};
    param.mode = GET_DATA_MODE_ALL_IN_ONE_PIN_AUTH;
    std::vector<uint8_t> testData = {6, 7, 8, 9, 10, 11};
    constexpr int32_t testErrorCode = 0;

    std::vector<uint8_t> testSalt = {6, 7, 8, 9, 10, 11};
    Scrypt scrypt(testSalt);
    std::vector<uint8_t> testSetData = scrypt.GetScrypt(testData, param.algoVersion);

    auto mockInputerSetData = GetMockInputerSetData(testAuthSubType, testSetData, testErrorCode);
    ASSERT_NE(mockInputerSetData, nullptr);
    InputerDataImpl inputerDataImpl(param);
    inputerDataImpl.OnSetData(testAuthSubType, testData);
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
