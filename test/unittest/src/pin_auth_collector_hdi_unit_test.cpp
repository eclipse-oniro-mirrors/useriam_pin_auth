/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"

#include "hdf_base.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#include "pin_auth_collector_hdi.h"
#include "iam_common_defines.h"
#include "mock_iexecute_callback.h"
#include "mock_icollector_executor.h"

#define LOG_TAG "PIN_AUTH_SA"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::UserIam::Common;

namespace OHOS {
namespace UserIam {
namespace PinAuth {
using IamResultCode = OHOS::UserIam::UserAuth::ResultCode;
using IamExecutorRole = OHOS::UserIam::UserAuth::ExecutorRole;
using IamExecutorInfo = OHOS::UserIam::UserAuth::ExecutorInfo;
using IamAuthType = OHOS::UserIam::UserAuth::AuthType;
using IamExecutorSecureLevel = OHOS::UserIam::UserAuth::ExecutorSecureLevel;
using IamPropertyMode = OHOS::UserIam::UserAuth::PropertyMode;
namespace {
static const std::map<HDF_STATUS, IamResultCode> RESULT_CODE_MAP = {
    {HDF_SUCCESS, UserAuth::ResultCode::SUCCESS},
    {HDF_FAILURE, UserAuth::ResultCode::GENERAL_ERROR},
    {HDF_ERR_TIMEOUT, UserAuth::ResultCode::TIMEOUT},
    {HDF_ERR_QUEUE_FULL, UserAuth::ResultCode::BUSY},
    {HDF_ERR_DEVICE_BUSY, UserAuth::ResultCode::BUSY},
    {HDF_ERR_INVALID_PARAM, UserAuth::ResultCode::INVALID_PARAMETERS},
};
}

class PinAuthCollectorHdiUnitTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void PinAuthCollectorHdiUnitTest::SetUpTestCase()
{
}

void PinAuthCollectorHdiUnitTest::TearDownTestCase()
{
}

void PinAuthCollectorHdiUnitTest::SetUp()
{
}

void PinAuthCollectorHdiUnitTest::TearDown()
{
}

HWTEST_F(PinAuthCollectorHdiUnitTest, PinAuthCollectorExecutorHdi_GetExecutorInfo_001, TestSize.Level0)
{
    auto executorProxy = new (std::nothrow) MockICollectorExecutor();
    ASSERT_TRUE(executorProxy != nullptr);
    EXPECT_CALL(*executorProxy, GetExecutorInfo(_)).Times(Exactly(1)).WillOnce([](ExecutorInfo &info) {
        info = {
            .executorRole = ExecutorRole::COLLECTOR,
            .authType = AuthType::PIN,
            .esl = ExecutorSecureLevel::ESL0,
        };
        return HDF_SUCCESS;
    });
    PinAuthCollectorHdi collectorHdi(executorProxy);
    IamExecutorInfo info = {};
    auto ret = collectorHdi.GetExecutorInfo(info);
    EXPECT_TRUE(info.executorRole == IamExecutorRole::COLLECTOR);
    EXPECT_TRUE(info.authType == IamAuthType::PIN);
    EXPECT_TRUE(info.esl == IamExecutorSecureLevel::ESL0);
    EXPECT_TRUE(ret == IamResultCode::SUCCESS);
}

HWTEST_F(PinAuthCollectorHdiUnitTest, PinAuthCollectorExecutorHdi_GetExecutorInfo_002, TestSize.Level0)
{
    for (const auto &pair : RESULT_CODE_MAP) {
        auto executorProxy = new (std::nothrow) MockICollectorExecutor();
        ASSERT_TRUE(executorProxy != nullptr);
        EXPECT_CALL(*executorProxy, GetExecutorInfo(_))
            .Times(Exactly(1))
            .WillOnce([&pair](ExecutorInfo &info) {
                info = {
                    .executorRole = ExecutorRole::COLLECTOR,
                    .authType = AuthType::PIN,
                    .esl = ExecutorSecureLevel::ESL0,
                };
                return static_cast<int32_t>(pair.first);
            });
        PinAuthCollectorHdi collectorHdi(executorProxy);
        IamExecutorInfo info = {};
        auto ret = collectorHdi.GetExecutorInfo(info);
        EXPECT_TRUE(ret == pair.second);
    }
}

HWTEST_F(PinAuthCollectorHdiUnitTest, PinAuthCollectorExecutorHdi_GetExecutorInfo_003, TestSize.Level0)
{
    static const std::map<AuthType, pair<IamAuthType, IamResultCode>> data = {
        {AuthType::PIN, {IamAuthType::PIN, IamResultCode::SUCCESS}},
        {static_cast<AuthType>(AuthType::PIN + 1),
            {IamAuthType::PIN, IamResultCode::GENERAL_ERROR}},
        {static_cast<AuthType>(AuthType::PIN - 1),
            {IamAuthType::PIN, IamResultCode::GENERAL_ERROR}},
    };
    for (const auto &pair : data) {
        auto executorProxy = new (std::nothrow) MockICollectorExecutor();
        ASSERT_TRUE(executorProxy != nullptr);
        EXPECT_CALL(*executorProxy, GetExecutorInfo(_))
            .Times(Exactly(1))
            .WillOnce([&pair](ExecutorInfo &info) {
                info = {
                    .executorRole = ExecutorRole::COLLECTOR,
                    .authType = pair.first,
                    .esl = ExecutorSecureLevel::ESL0,
                };
                return HDF_SUCCESS;
            });
        PinAuthCollectorHdi collectorHdi(executorProxy);
        IamExecutorInfo info = {};
        auto ret = collectorHdi.GetExecutorInfo(info);
        EXPECT_TRUE(ret == pair.second.second);
        if (ret == IamResultCode::SUCCESS) {
            EXPECT_TRUE(info.authType == pair.second.first);
        }
    }
}

HWTEST_F(PinAuthCollectorHdiUnitTest, PinAuthCollectorExecutorHdi_GetExecutorInfo_004, TestSize.Level0)
{
    static const std::map<ExecutorRole, pair<IamExecutorRole, IamResultCode>> data = {
        {ExecutorRole::COLLECTOR, {IamExecutorRole::COLLECTOR, IamResultCode::SUCCESS}},
        {ExecutorRole::VERIFIER, {IamExecutorRole::VERIFIER, IamResultCode::SUCCESS}},
        {ExecutorRole::ALL_IN_ONE, {IamExecutorRole::ALL_IN_ONE, IamResultCode::SUCCESS}},
        {static_cast<ExecutorRole>(ExecutorRole::COLLECTOR - 1),
            {IamExecutorRole::COLLECTOR, IamResultCode::GENERAL_ERROR}},
        {static_cast<ExecutorRole>(ExecutorRole::COLLECTOR + 1),
            {IamExecutorRole::COLLECTOR, IamResultCode::GENERAL_ERROR}},
    };
    for (const auto &pair : data) {
        auto executorProxy = new (std::nothrow) MockICollectorExecutor();
        ASSERT_TRUE(executorProxy != nullptr);
        EXPECT_CALL(*executorProxy, GetExecutorInfo(_))
            .Times(Exactly(1))
            .WillOnce([&pair](ExecutorInfo &info) {
                info = {
                    .executorRole = pair.first,
                    .authType = AuthType::PIN,
                    .esl = ExecutorSecureLevel::ESL0,
                };
                return HDF_SUCCESS;
            });
        PinAuthCollectorHdi collectorHdi(executorProxy);
        IamExecutorInfo info = {};
        auto ret = collectorHdi.GetExecutorInfo(info);
        EXPECT_TRUE(ret == pair.second.second);
        if (ret == IamResultCode::SUCCESS) {
            EXPECT_TRUE(info.executorRole == pair.second.first);
        }
    }
}

HWTEST_F(PinAuthCollectorHdiUnitTest, PinAuthCollectorExecutorHdi_GetExecutorInfo_005, TestSize.Level0)
{
    static const std::map<ExecutorSecureLevel, pair<IamExecutorSecureLevel, IamResultCode>> data =
        {
            {ExecutorSecureLevel::ESL0, {IamExecutorSecureLevel::ESL0, IamResultCode::SUCCESS}},
            {ExecutorSecureLevel::ESL1, {IamExecutorSecureLevel::ESL1, IamResultCode::SUCCESS}},
            {ExecutorSecureLevel::ESL2, {IamExecutorSecureLevel::ESL2, IamResultCode::SUCCESS}},
            {ExecutorSecureLevel::ESL3, {IamExecutorSecureLevel::ESL3, IamResultCode::SUCCESS}},
            {static_cast<ExecutorSecureLevel>(ExecutorSecureLevel::ESL0 - 1),
                {IamExecutorSecureLevel::ESL3, IamResultCode::GENERAL_ERROR}},
            {static_cast<ExecutorSecureLevel>(ExecutorSecureLevel::ESL3 + 1),
                {IamExecutorSecureLevel::ESL3, IamResultCode::GENERAL_ERROR}},
        };
    for (const auto &pair : data) {
        auto executorProxy = new (std::nothrow) MockICollectorExecutor();
        ASSERT_TRUE(executorProxy != nullptr);
        EXPECT_CALL(*executorProxy, GetExecutorInfo(_))
            .Times(Exactly(1))
            .WillOnce([&pair](ExecutorInfo &info) {
                info = {
                    .executorRole = ExecutorRole::COLLECTOR,
                    .authType = AuthType::PIN,
                    .esl = pair.first,
                };
                return HDF_SUCCESS;
            });
        PinAuthCollectorHdi collectorHdi(executorProxy);
        IamExecutorInfo info = {};
        auto ret = collectorHdi.GetExecutorInfo(info);
        EXPECT_TRUE(ret == pair.second.second);
        if (ret == IamResultCode::SUCCESS) {
            EXPECT_TRUE(info.esl == pair.second.first);
        }
    }
}

HWTEST_F(PinAuthCollectorHdiUnitTest, PinAuthCollectorExecutorHdi_GetExecutorInfo_006, TestSize.Level0)
{
    PinAuthCollectorHdi collectorHdi(nullptr);
    IamExecutorInfo info = {};
    auto ret = collectorHdi.GetExecutorInfo(info);
    EXPECT_TRUE(ret == IamResultCode::GENERAL_ERROR);
}

HWTEST_F(PinAuthCollectorHdiUnitTest, PinAuthCollectorExecutorHdi_OnRegisterFinish_001, TestSize.Level0)
{
    for (const auto &pair : RESULT_CODE_MAP) {
        auto executorProxy = new (std::nothrow) MockICollectorExecutor();
        ASSERT_TRUE(executorProxy != nullptr);
        EXPECT_CALL(*executorProxy, OnRegisterFinish(_, _, _))
            .Times(Exactly(1))
            .WillOnce(
                [&pair](const std::vector<uint64_t> &templateIdList, const std::vector<uint8_t> &frameworkPublicKey,
                    const std::vector<uint8_t> &extraInfo) { return pair.first; });
        PinAuthCollectorHdi collectorHdi(executorProxy);
        auto ret =
            collectorHdi.OnRegisterFinish(std::vector<uint64_t>(), std::vector<uint8_t>(), std::vector<uint8_t>());
        EXPECT_TRUE(ret == pair.second);
    }
}

HWTEST_F(PinAuthCollectorHdiUnitTest, PinAuthCollectorExecutorHdi_OnRegisterFinish_002, TestSize.Level0)
{
    PinAuthCollectorHdi collectorHdi(nullptr);
    auto ret = collectorHdi.OnRegisterFinish(std::vector<uint64_t>(), std::vector<uint8_t>(), std::vector<uint8_t>());
    EXPECT_TRUE(ret == IamResultCode::GENERAL_ERROR);
}

HWTEST_F(PinAuthCollectorHdiUnitTest, PinAuthCollectorExecutorHdi_OnSetData_001, TestSize.Level0)
{
    for (const auto &pair : RESULT_CODE_MAP) {
        auto executorProxy = new (std::nothrow) MockICollectorExecutor();
        ASSERT_TRUE(executorProxy != nullptr);
        EXPECT_CALL(*executorProxy, SetData(_, _, _, _))
            .Times(Exactly(1))
            .WillOnce([&pair](uint64_t scheduleId, uint64_t authSubType, const std::vector<uint8_t>& data,
                int32_t resultCode)
                    { return pair.first; });
        PinAuthCollectorHdi collectorHdi(executorProxy);
        auto ret = collectorHdi.OnSetData(0, 0, std::vector<uint8_t>(), 0);
        EXPECT_TRUE(ret == pair.second);
    }
}

HWTEST_F(PinAuthCollectorHdiUnitTest, PinAuthCollectorExecutorHdi_OnSetData_002, TestSize.Level0)
{
    PinAuthCollectorHdi collectorHdi(nullptr);
    auto ret = collectorHdi.OnSetData(0, 0, std::vector<uint8_t>(), 0);
    EXPECT_TRUE(ret == IamResultCode::GENERAL_ERROR);
}

HWTEST_F(PinAuthCollectorHdiUnitTest, PinAuthCollectorExecutorHdi_Cancel_001, TestSize.Level0)
{
    for (const auto &pair : RESULT_CODE_MAP) {
        auto executorProxy = new (std::nothrow) MockICollectorExecutor();
        ASSERT_TRUE(executorProxy != nullptr);
        EXPECT_CALL(*executorProxy, Cancel(_)).Times(Exactly(1)).WillOnce([&pair](uint64_t scheduleId) {
            return pair.first;
        });
        PinAuthCollectorHdi collectorHdi(executorProxy);
        auto ret = collectorHdi.Cancel(0);
        EXPECT_TRUE(ret == pair.second);
    }
}

HWTEST_F(PinAuthCollectorHdiUnitTest, PinAuthCollectorExecutorHdi_Cancel_002, TestSize.Level0)
{
    PinAuthCollectorHdi collectorHdi(nullptr);
    auto ret = collectorHdi.Cancel(0);
    EXPECT_TRUE(ret == IamResultCode::GENERAL_ERROR);
}

HWTEST_F(PinAuthCollectorHdiUnitTest, PinAuthCollectorExecutorHdi_SendMessage_001, TestSize.Level0)
{
    auto executorProxy = new (std::nothrow) MockICollectorExecutor();
    ASSERT_TRUE(executorProxy != nullptr);
    PinAuthCollectorHdi collectorHdi(executorProxy);
    std::vector<uint8_t> data;
    auto ret = collectorHdi.SendMessage(1, 1, data);
    EXPECT_TRUE(ret == IamResultCode::SUCCESS);
}

HWTEST_F(PinAuthCollectorHdiUnitTest, PinAuthCollectorExecutorHdi_SendMessage_002, TestSize.Level0)
{
    PinAuthCollectorHdi collectorHdi(nullptr);
    std::vector<uint8_t> data;
    auto ret = collectorHdi.SendMessage(1, 1, data);
    EXPECT_TRUE(ret == IamResultCode::GENERAL_ERROR);
}

HWTEST_F(PinAuthCollectorHdiUnitTest, PinAuthCollectorExecutorHdi_Collect_001, TestSize.Level0)
{
    for (const auto &pair : RESULT_CODE_MAP) {
        auto executorProxy = new (std::nothrow) MockICollectorExecutor();
        ASSERT_TRUE(executorProxy != nullptr);
        EXPECT_CALL(*executorProxy, Collect(_, _, _))
            .Times(Exactly(1))
            .WillOnce([&pair](uint64_t scheduleId, const std::vector<uint8_t> &extraInfo,
                          const sptr<IExecutorCallback> &callbackObj) { return pair.first; });
        auto collectorHdi = MakeShared<PinAuthCollectorHdi>(executorProxy);
        ASSERT_TRUE(collectorHdi != nullptr);
        auto executeCallback = MakeShared<UserIam::UserAuth::MockIExecuteCallback>();
        ASSERT_TRUE(executeCallback != nullptr);
        auto ret = collectorHdi->Collect(0, UserAuth::CollectParam{0, std::vector<uint8_t>()}, executeCallback);
        EXPECT_TRUE(ret == pair.second);
    }
}

HWTEST_F(PinAuthCollectorHdiUnitTest, PinAuthCollectorExecutorHdi_Collect_002, TestSize.Level0)
{
    auto executorProxy = new (std::nothrow) MockICollectorExecutor();
    ASSERT_TRUE(executorProxy != nullptr);
    auto collectorHdi = MakeShared<PinAuthCollectorHdi>(executorProxy);
    ASSERT_TRUE(collectorHdi != nullptr);
    auto ret = collectorHdi->Collect(0, UserAuth::CollectParam{0, std::vector<uint8_t>()}, nullptr);
    EXPECT_TRUE(ret == IamResultCode::GENERAL_ERROR);
}

HWTEST_F(PinAuthCollectorHdiUnitTest, PinAuthCollectorExecutorHdi_Collect_003, TestSize.Level0)
{
    auto collectorHdi = MakeShared<PinAuthCollectorHdi>(nullptr);
    ASSERT_TRUE(collectorHdi != nullptr);
    auto executeCallback = MakeShared<UserIam::UserAuth::MockIExecuteCallback>();
    ASSERT_TRUE(executeCallback != nullptr);
    auto ret = collectorHdi->Collect(0, UserAuth::CollectParam{0, std::vector<uint8_t>()}, executeCallback);
    EXPECT_TRUE(ret == IamResultCode::GENERAL_ERROR);
}

HWTEST_F(PinAuthCollectorHdiUnitTest, PinAuthCollectorExecutorHdi_Collect_004, TestSize.Level0)
{
    PinAuthCollectorHdi collectorHdi(nullptr);
    auto ret = collectorHdi.Collect(0, UserAuth::CollectParam{0, std::vector<uint8_t>()}, nullptr);
    EXPECT_TRUE(ret == IamResultCode::GENERAL_ERROR);
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
