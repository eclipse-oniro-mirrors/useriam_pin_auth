/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "pin_auth_verifier_hdi.h"
#include "iam_common_defines.h"
#include "mock_iexecute_callback.h"
#include "mock_iverifier_executor.h"

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

class PinAuthVerifierHdiUnitTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void PinAuthVerifierHdiUnitTest::SetUpTestCase()
{
}

void PinAuthVerifierHdiUnitTest::TearDownTestCase()
{
}

void PinAuthVerifierHdiUnitTest::SetUp()
{
}

void PinAuthVerifierHdiUnitTest::TearDown()
{
}

HWTEST_F(PinAuthVerifierHdiUnitTest, PinAuthVerifierExecutorHdi_GetExecutorInfo_001, TestSize.Level0)
{
    auto executorProxy = new (std::nothrow) MockIVerifyExecutor();
    ASSERT_TRUE(executorProxy != nullptr);
    EXPECT_CALL(*executorProxy, GetExecutorInfo(_)).Times(Exactly(1)).WillOnce([](ExecutorInfo &info) {
        info = {
            .executorRole = ExecutorRole::VERIFIER,
            .authType = AuthType::PIN,
            .esl = ExecutorSecureLevel::ESL0,
        };
        return HDF_SUCCESS;
    });
    PinAuthVerifierHdi verifyHdi(executorProxy);
    IamExecutorInfo info = {};
    auto ret = verifyHdi.GetExecutorInfo(info);
    EXPECT_TRUE(info.executorRole == IamExecutorRole::VERIFIER);
    EXPECT_TRUE(info.authType == IamAuthType::PIN);
    EXPECT_TRUE(info.esl == IamExecutorSecureLevel::ESL0);
    EXPECT_TRUE(ret == IamResultCode::SUCCESS);
}

HWTEST_F(PinAuthVerifierHdiUnitTest, PinAuthVerifierExecutorHdi_GetExecutorInfo_002, TestSize.Level0)
{
    for (const auto &pair : RESULT_CODE_MAP) {
        auto executorProxy = new (std::nothrow) MockIVerifyExecutor();
        ASSERT_TRUE(executorProxy != nullptr);
        EXPECT_CALL(*executorProxy, GetExecutorInfo(_))
            .Times(Exactly(1))
            .WillOnce([&pair](ExecutorInfo &info) {
                info = {
                    .executorRole = ExecutorRole::VERIFIER,
                    .authType = AuthType::PIN,
                    .esl = ExecutorSecureLevel::ESL0,
                };
                return static_cast<int32_t>(pair.first);
            });
        PinAuthVerifierHdi verifyHdi(executorProxy);
        IamExecutorInfo info = {};
        auto ret = verifyHdi.GetExecutorInfo(info);
        EXPECT_TRUE(ret == pair.second);
    }
}

HWTEST_F(PinAuthVerifierHdiUnitTest, PinAuthVerifierExecutorHdi_GetExecutorInfo_003, TestSize.Level0)
{
    static const std::map<AuthType, pair<IamAuthType, IamResultCode>> data = {
        {AuthType::PIN, {IamAuthType::PIN, IamResultCode::SUCCESS}},
        {static_cast<AuthType>(AuthType::PIN + 1),
            {IamAuthType::PIN, IamResultCode::GENERAL_ERROR}},
        {static_cast<AuthType>(AuthType::PIN - 1),
            {IamAuthType::PIN, IamResultCode::GENERAL_ERROR}},
    };
    for (const auto &pair : data) {
        auto executorProxy = new (std::nothrow) MockIVerifyExecutor();
        ASSERT_TRUE(executorProxy != nullptr);
        EXPECT_CALL(*executorProxy, GetExecutorInfo(_))
            .Times(Exactly(1))
            .WillOnce([&pair](ExecutorInfo &info) {
                info = {
                    .executorRole = ExecutorRole::VERIFIER,
                    .authType = pair.first,
                    .esl = ExecutorSecureLevel::ESL0,
                };
                return HDF_SUCCESS;
            });
        PinAuthVerifierHdi verifyHdi(executorProxy);
        IamExecutorInfo info = {};
        auto ret = verifyHdi.GetExecutorInfo(info);
        EXPECT_TRUE(ret == pair.second.second);
        if (ret == IamResultCode::SUCCESS) {
            EXPECT_TRUE(info.authType == pair.second.first);
        }
    }
}

HWTEST_F(PinAuthVerifierHdiUnitTest, PinAuthVerifierExecutorHdi_GetExecutorInfo_004, TestSize.Level0)
{
    static const std::map<ExecutorRole, pair<IamExecutorRole, IamResultCode>> data = {
        {ExecutorRole::COLLECTOR, {IamExecutorRole::COLLECTOR, IamResultCode::SUCCESS}},
        {ExecutorRole::VERIFIER, {IamExecutorRole::VERIFIER, IamResultCode::SUCCESS}},
        {ExecutorRole::ALL_IN_ONE, {IamExecutorRole::ALL_IN_ONE, IamResultCode::SUCCESS}},
        {static_cast<ExecutorRole>(ExecutorRole::VERIFIER - 1),
            {IamExecutorRole::VERIFIER, IamResultCode::GENERAL_ERROR}},
        {static_cast<ExecutorRole>(ExecutorRole::VERIFIER + 1),
            {IamExecutorRole::VERIFIER, IamResultCode::GENERAL_ERROR}},
    };
    for (const auto &pair : data) {
        auto executorProxy = new (std::nothrow) MockIVerifyExecutor();
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
        PinAuthVerifierHdi verifyHdi(executorProxy);
        IamExecutorInfo info = {};
        auto ret = verifyHdi.GetExecutorInfo(info);
        EXPECT_TRUE(ret == pair.second.second);
        if (ret == IamResultCode::SUCCESS) {
            EXPECT_TRUE(info.executorRole == pair.second.first);
        }
    }
}

HWTEST_F(PinAuthVerifierHdiUnitTest, PinAuthVerifierExecutorHdi_GetExecutorInfo_005, TestSize.Level0)
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
        auto executorProxy = new (std::nothrow) MockIVerifyExecutor();
        ASSERT_TRUE(executorProxy != nullptr);
        EXPECT_CALL(*executorProxy, GetExecutorInfo(_))
            .Times(Exactly(1))
            .WillOnce([&pair](ExecutorInfo &info) {
                info = {
                    .executorRole = ExecutorRole::VERIFIER,
                    .authType = AuthType::PIN,
                    .esl = pair.first,
                };
                return HDF_SUCCESS;
            });
        PinAuthVerifierHdi verifyHdi(executorProxy);
        IamExecutorInfo info = {};
        auto ret = verifyHdi.GetExecutorInfo(info);
        EXPECT_TRUE(ret == pair.second.second);
        if (ret == IamResultCode::SUCCESS) {
            EXPECT_TRUE(info.esl == pair.second.first);
        }
    }
}

HWTEST_F(PinAuthVerifierHdiUnitTest, PinAuthVerifierExecutorHdi_GetExecutorInfo_006, TestSize.Level0)
{
    PinAuthVerifierHdi verifyHdi(nullptr);
    IamExecutorInfo info = {};
    auto ret = verifyHdi.GetExecutorInfo(info);
    EXPECT_TRUE(ret == IamResultCode::GENERAL_ERROR);
}

HWTEST_F(PinAuthVerifierHdiUnitTest, PinAuthVerifierExecutorHdi_OnRegisterFinish_001, TestSize.Level0)
{
    for (const auto &pair : RESULT_CODE_MAP) {
        auto executorProxy = new (std::nothrow) MockIVerifyExecutor();
        ASSERT_TRUE(executorProxy != nullptr);
        EXPECT_CALL(*executorProxy, OnRegisterFinish(_, _, _))
            .Times(Exactly(1))
            .WillOnce(
                [&pair](const std::vector<uint64_t> &templateIdList, const std::vector<uint8_t> &frameworkPublicKey,
                    const std::vector<uint8_t> &extraInfo) { return pair.first; });
        PinAuthVerifierHdi verifyHdi(executorProxy);
        auto ret =
            verifyHdi.OnRegisterFinish(std::vector<uint64_t>(), std::vector<uint8_t>(), std::vector<uint8_t>());
        EXPECT_TRUE(ret == pair.second);
    }
}

HWTEST_F(PinAuthVerifierHdiUnitTest, PinAuthVerifierExecutorHdi_OnRegisterFinish_002, TestSize.Level0)
{
    PinAuthVerifierHdi verifyHdi(nullptr);
    auto ret = verifyHdi.OnRegisterFinish(std::vector<uint64_t>(), std::vector<uint8_t>(), std::vector<uint8_t>());
    EXPECT_TRUE(ret == IamResultCode::GENERAL_ERROR);
}

HWTEST_F(PinAuthVerifierHdiUnitTest, PinAuthVerifierExecutorHdi_Authenticate_001, TestSize.Level0)
{
    for (const auto &pair : RESULT_CODE_MAP) {
        auto executorProxy = new (std::nothrow) MockIVerifyExecutor();
        ASSERT_TRUE(executorProxy != nullptr);
        EXPECT_CALL(*executorProxy, Authenticate(_, _, _, _)).Times(Exactly(1)).WillOnce([&pair](
            uint64_t scheduleId, const std::vector<uint64_t>& templateIdList, const std::vector<uint8_t> &extraInfo,
            const sptr<IExecutorCallback> &callbackObj) { return pair.first; });
        auto verifyHdi = MakeShared<PinAuthVerifierHdi>(executorProxy);
        ASSERT_TRUE(verifyHdi != nullptr);
        auto executeCallback = MakeShared<UserIam::UserAuth::MockIExecuteCallback>();
        ASSERT_TRUE(executeCallback != nullptr);
        const std::vector<uint64_t> templateIdList = {1, 2};
        auto ret = verifyHdi->Authenticate(0,
            UserAuth::AuthenticateParam{0, templateIdList, std::vector<uint8_t>()}, executeCallback);
        EXPECT_TRUE(ret == pair.second);
    }
}

HWTEST_F(PinAuthVerifierHdiUnitTest, PinAuthVerifierExecutorHdi_Authenticate_002, TestSize.Level0)
{
    auto executorProxy = new (std::nothrow) MockIVerifyExecutor();
    ASSERT_TRUE(executorProxy != nullptr);
    auto verifyHdi = MakeShared<PinAuthVerifierHdi>(executorProxy);
    auto ret = verifyHdi->Authenticate(0,
        UserAuth::AuthenticateParam{0, std::vector<uint64_t>(), std::vector<uint8_t>()}, nullptr);
    EXPECT_TRUE(ret == IamResultCode::GENERAL_ERROR);
}

HWTEST_F(PinAuthVerifierHdiUnitTest, PinAuthVerifierExecutorHdi_Authenticate_003, TestSize.Level0)
{
    auto verifyHdi = MakeShared<PinAuthVerifierHdi>(nullptr);
    auto executeCallback = MakeShared<UserIam::UserAuth::MockIExecuteCallback>();
    ASSERT_TRUE(executeCallback != nullptr);
    auto ret = verifyHdi->Authenticate(0,
        UserAuth::AuthenticateParam{0, std::vector<uint64_t>(), std::vector<uint8_t>()}, executeCallback);
    EXPECT_TRUE(ret == IamResultCode::GENERAL_ERROR);
}

HWTEST_F(PinAuthVerifierHdiUnitTest, PinAuthVerifierExecutorHdi_Authenticate_004, TestSize.Level0)
{
    PinAuthVerifierHdi verifyHdi(nullptr);
    auto ret = verifyHdi.Authenticate(0,
        UserAuth::AuthenticateParam{0, std::vector<uint64_t>(), std::vector<uint8_t>()}, nullptr);
    EXPECT_TRUE(ret == IamResultCode::GENERAL_ERROR);
}

HWTEST_F(PinAuthVerifierHdiUnitTest, PinAuthVerifierExecutorHdi_Cancel_001, TestSize.Level0)
{
    for (const auto &pair : RESULT_CODE_MAP) {
        auto executorProxy = new (std::nothrow) MockIVerifyExecutor();
        ASSERT_TRUE(executorProxy != nullptr);
        EXPECT_CALL(*executorProxy, Cancel(_)).Times(Exactly(1)).WillOnce([&pair](uint64_t scheduleId) {
            return pair.first;
        });
        PinAuthVerifierHdi verifyHdi(executorProxy);
        auto ret = verifyHdi.Cancel(0);
        EXPECT_TRUE(ret == pair.second);
    }
}

HWTEST_F(PinAuthVerifierHdiUnitTest, PinAuthVerifierExecutorHdi_Cancel_002, TestSize.Level0)
{
    PinAuthVerifierHdi verifyHdi(nullptr);
    auto ret = verifyHdi.Cancel(0);
    EXPECT_TRUE(ret == IamResultCode::GENERAL_ERROR);
}

HWTEST_F(PinAuthVerifierHdiUnitTest, PinAuthVerifierExecutorHdi_SendMessage_001, TestSize.Level0)
{
    auto executorProxy = new (std::nothrow) MockIVerifyExecutor();
    ASSERT_TRUE(executorProxy != nullptr);
    PinAuthVerifierHdi verifyHdi(executorProxy);
    std::vector<uint8_t> data;
    auto ret = verifyHdi.SendMessage(1, 1, data);
    EXPECT_TRUE(ret == IamResultCode::SUCCESS);
}

HWTEST_F(PinAuthVerifierHdiUnitTest, PinAuthVerifierExecutorHdi_SendMessage_002, TestSize.Level0)
{
    PinAuthVerifierHdi verifyHdi(nullptr);
    std::vector<uint8_t> data;
    auto ret = verifyHdi.SendMessage(1, 1, data);
    EXPECT_TRUE(ret == IamResultCode::GENERAL_ERROR);
}

HWTEST_F(PinAuthVerifierHdiUnitTest, PinAuthVerifierExecutorHdi_NotifyCollectorReady_001, TestSize.Level0)
{
    for (const auto &pair : RESULT_CODE_MAP) {
        auto executorProxy = new (std::nothrow) MockIVerifyExecutor();
        ASSERT_TRUE(executorProxy != nullptr);
        EXPECT_CALL(*executorProxy, NotifyCollectorReady(_)).Times(Exactly(1)).WillOnce([&pair](uint64_t scheduleId) {
            return pair.first;
        });
        PinAuthVerifierHdi verifyHdi(executorProxy);
        auto ret = verifyHdi.NotifyCollectorReady(0);
        EXPECT_TRUE(ret == pair.second);
    }
}

HWTEST_F(PinAuthVerifierHdiUnitTest, PinAuthVerifierExecutorHdi_NotifyCollectorReady_002, TestSize.Level0)
{
    PinAuthVerifierHdi verifyHdi(nullptr);
    auto ret = verifyHdi.NotifyCollectorReady(0);
    EXPECT_TRUE(ret == IamResultCode::GENERAL_ERROR);
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
