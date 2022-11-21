/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "pin_auth_executor_hdi.h"
#include "iam_common_defines.h"
#include "mock_iexecute_callback.h"
#include "mock_iexecutor.h"

#define LOG_LABEL OHOS::UserIam::Common::LABEL_PIN_AUTH_SA

using namespace testing;
using namespace testing::ext;
using namespace OHOS::UserIam::Common;
namespace PinHdi = OHOS::HDI::PinAuth::V1_0;

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
    {HDF_SUCCESS, IamResultCode::SUCCESS},
    {HDF_FAILURE, IamResultCode::FAIL},
    {HDF_ERR_TIMEOUT, IamResultCode::TIMEOUT},
    {HDF_ERR_QUEUE_FULL, IamResultCode::BUSY},
    {HDF_ERR_DEVICE_BUSY, IamResultCode::BUSY}
};
}

class PinAuthExecutorHdiUnitTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void PinAuthExecutorHdiUnitTest::SetUpTestCase()
{
}

void PinAuthExecutorHdiUnitTest::TearDownTestCase()
{
}

void PinAuthExecutorHdiUnitTest::SetUp()
{
}

void PinAuthExecutorHdiUnitTest::TearDown()
{
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_GetExecutorInfo_001, TestSize.Level0)
{
    auto executorProxy = new (std::nothrow) PinHdi::MockIExecutor();
    ASSERT_TRUE(executorProxy != nullptr);
    EXPECT_CALL(*executorProxy, GetExecutorInfo(_)).Times(Exactly(1)).WillOnce([](PinHdi::ExecutorInfo &info) {
        info = {
            .executorRole = PinHdi::ExecutorRole::ALL_IN_ONE,
            .authType = PinHdi::PIN,
            .esl = PinHdi::ExecutorSecureLevel::ESL0,
        };
        return HDF_SUCCESS;
    });
    PinAuthExecutorHdi executorHdi(executorProxy);
    IamExecutorInfo info = {};
    auto ret = executorHdi.GetExecutorInfo(info);
    EXPECT_TRUE(info.executorRole == IamExecutorRole::ALL_IN_ONE);
    EXPECT_TRUE(info.authType == IamAuthType::PIN);
    EXPECT_TRUE(info.esl == IamExecutorSecureLevel::ESL0);
    EXPECT_TRUE(ret == IamResultCode::SUCCESS);
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_GetExecutorInfo_002, TestSize.Level0)
{
    for (const auto &pair : RESULT_CODE_MAP) {
        auto executorProxy = new (std::nothrow) PinHdi::MockIExecutor();
        ASSERT_TRUE(executorProxy != nullptr);
        EXPECT_CALL(*executorProxy, GetExecutorInfo(_))
            .Times(Exactly(1))
            .WillOnce([&pair](PinHdi::ExecutorInfo &info) {
                info = {
                    .executorRole = PinHdi::ExecutorRole::ALL_IN_ONE,
                    .authType = PinHdi::PIN,
                    .esl = PinHdi::ExecutorSecureLevel::ESL0,
                };
                return static_cast<int32_t>(pair.first);
            });
        PinAuthExecutorHdi executorHdi(executorProxy);
        IamExecutorInfo info = {};
        auto ret = executorHdi.GetExecutorInfo(info);
        EXPECT_TRUE(ret == pair.second);
    }
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_GetExecutorInfo_003, TestSize.Level0)
{
    static const std::map<PinHdi::AuthType, pair<IamAuthType, IamResultCode>> data = {
        {PinHdi::PIN, {IamAuthType::PIN, IamResultCode::SUCCESS}},
        {static_cast<PinHdi::AuthType>(PinHdi::PIN + 1),
            {IamAuthType::PIN, IamResultCode::GENERAL_ERROR}},
        {static_cast<PinHdi::AuthType>(PinHdi::PIN - 1),
            {IamAuthType::PIN, IamResultCode::GENERAL_ERROR}},
    };
    for (const auto &pair : data) {
        auto executorProxy = new (std::nothrow) PinHdi::MockIExecutor();
        ASSERT_TRUE(executorProxy != nullptr);
        EXPECT_CALL(*executorProxy, GetExecutorInfo(_))
            .Times(Exactly(1))
            .WillOnce([&pair](PinHdi::ExecutorInfo &info) {
                info = {
                    .executorRole = PinHdi::ExecutorRole::ALL_IN_ONE,
                    .authType = pair.first,
                    .esl = PinHdi::ExecutorSecureLevel::ESL0,
                };
                return HDF_SUCCESS;
            });
        PinAuthExecutorHdi executorHdi(executorProxy);
        IamExecutorInfo info = {};
        auto ret = executorHdi.GetExecutorInfo(info);
        EXPECT_TRUE(ret == pair.second.second);
        if (ret == IamResultCode::SUCCESS) {
            EXPECT_TRUE(info.authType == pair.second.first);
        }
    }
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_GetExecutorInfo_004, TestSize.Level0)
{
    static const std::map<PinHdi::ExecutorRole, pair<IamExecutorRole, IamResultCode>> data = {
        {PinHdi::ExecutorRole::COLLECTOR, {IamExecutorRole::COLLECTOR, IamResultCode::SUCCESS}},
        {PinHdi::ExecutorRole::VERIFIER, {IamExecutorRole::VERIFIER, IamResultCode::SUCCESS}},
        {PinHdi::ExecutorRole::ALL_IN_ONE, {IamExecutorRole::ALL_IN_ONE, IamResultCode::SUCCESS}},
        {static_cast<PinHdi::ExecutorRole>(PinHdi::ExecutorRole::COLLECTOR - 1),
            {IamExecutorRole::ALL_IN_ONE, IamResultCode::GENERAL_ERROR}},
        {static_cast<PinHdi::ExecutorRole>(PinHdi::ExecutorRole::ALL_IN_ONE + 1),
            {IamExecutorRole::ALL_IN_ONE, IamResultCode::GENERAL_ERROR}},
    };
    for (const auto &pair : data) {
        auto executorProxy = new (std::nothrow) PinHdi::MockIExecutor();
        ASSERT_TRUE(executorProxy != nullptr);
        EXPECT_CALL(*executorProxy, GetExecutorInfo(_))
            .Times(Exactly(1))
            .WillOnce([&pair](PinHdi::ExecutorInfo &info) {
                info = {
                    .executorRole = pair.first,
                    .authType = PinHdi::PIN,
                    .esl = PinHdi::ExecutorSecureLevel::ESL0,
                };
                return HDF_SUCCESS;
            });
        PinAuthExecutorHdi executorHdi(executorProxy);
        IamExecutorInfo info = {};
        auto ret = executorHdi.GetExecutorInfo(info);
        EXPECT_TRUE(ret == pair.second.second);
        if (ret == IamResultCode::SUCCESS) {
            EXPECT_TRUE(info.executorRole == pair.second.first);
        }
    }
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_GetExecutorInfo_005, TestSize.Level0)
{
    static const std::map<PinHdi::ExecutorSecureLevel, pair<IamExecutorSecureLevel, IamResultCode>> data =
        {
            {PinHdi::ExecutorSecureLevel::ESL0, {IamExecutorSecureLevel::ESL0, IamResultCode::SUCCESS}},
            {PinHdi::ExecutorSecureLevel::ESL1, {IamExecutorSecureLevel::ESL1, IamResultCode::SUCCESS}},
            {PinHdi::ExecutorSecureLevel::ESL2, {IamExecutorSecureLevel::ESL2, IamResultCode::SUCCESS}},
            {PinHdi::ExecutorSecureLevel::ESL3, {IamExecutorSecureLevel::ESL3, IamResultCode::SUCCESS}},
            {static_cast<PinHdi::ExecutorSecureLevel>(PinHdi::ExecutorSecureLevel::ESL0 - 1),
                {IamExecutorSecureLevel::ESL3, IamResultCode::GENERAL_ERROR}},
            {static_cast<PinHdi::ExecutorSecureLevel>(PinHdi::ExecutorSecureLevel::ESL3 + 1),
                {IamExecutorSecureLevel::ESL3, IamResultCode::GENERAL_ERROR}},
        };
    for (const auto &pair : data) {
        auto executorProxy = new (std::nothrow) PinHdi::MockIExecutor();
        ASSERT_TRUE(executorProxy != nullptr);
        EXPECT_CALL(*executorProxy, GetExecutorInfo(_))
            .Times(Exactly(1))
            .WillOnce([&pair](PinHdi::ExecutorInfo &info) {
                info = {
                    .executorRole = PinHdi::ExecutorRole::ALL_IN_ONE,
                    .authType = PinHdi::PIN,
                    .esl = pair.first,
                };
                return HDF_SUCCESS;
            });
        PinAuthExecutorHdi executorHdi(executorProxy);
        IamExecutorInfo info = {};
        auto ret = executorHdi.GetExecutorInfo(info);
        EXPECT_TRUE(ret == pair.second.second);
        if (ret == IamResultCode::SUCCESS) {
            EXPECT_TRUE(info.esl == pair.second.first);
        }
    }
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_GetExecutorInfo_006, TestSize.Level0)
{
    PinAuthExecutorHdi executorHdi(nullptr);
    IamExecutorInfo info = {};
    auto ret = executorHdi.GetExecutorInfo(info);
    EXPECT_TRUE(ret == IamResultCode::GENERAL_ERROR);
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_GetTemplateInfo_001, TestSize.Level0)
{
    const UserAuth::TemplateInfo data = {.executorType = 1,
        .freezingTime = 2,
        .remainTimes = 3,
        .extraInfo = {4, 5, 6}};
    auto executorProxy = new (std::nothrow) PinHdi::MockIExecutor();
    ASSERT_TRUE(executorProxy != nullptr);
    EXPECT_CALL(*executorProxy, GetTemplateInfo(_, _))
        .Times(Exactly(1))
        .WillOnce([&data](uint64_t templateId, PinHdi::TemplateInfo &info) {
            info = {.executorType = data.executorType,
                .lockoutDuration = data.freezingTime,
                .remainAttempts = data.remainTimes,
                .extraInfo = data.extraInfo};
            return HDF_SUCCESS;
        });
    PinAuthExecutorHdi executorHdi(executorProxy);
    UserAuth::TemplateInfo info = {};
    auto ret = executorHdi.GetTemplateInfo(0, info);
    EXPECT_TRUE(ret == IamResultCode::SUCCESS);
    EXPECT_TRUE(info.executorType == data.executorType);
    EXPECT_TRUE(info.freezingTime == data.freezingTime);
    EXPECT_TRUE(info.remainTimes == data.remainTimes);
    EXPECT_TRUE(info.extraInfo == data.extraInfo);
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_GetTemplateInfo_002, TestSize.Level0)
{
    for (const auto &pair : RESULT_CODE_MAP) {
        auto executorProxy = new (std::nothrow) PinHdi::MockIExecutor();
        ASSERT_TRUE(executorProxy != nullptr);
        EXPECT_CALL(*executorProxy, GetTemplateInfo(_, _))
            .Times(Exactly(1))
            .WillOnce([&pair](uint64_t templateId, PinHdi::TemplateInfo &info) { return pair.first; });
        PinAuthExecutorHdi executorHdi(executorProxy);
        UserAuth::TemplateInfo info = {};
        auto ret = executorHdi.GetTemplateInfo(0, info);
        EXPECT_TRUE(ret == pair.second);
    }
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_GetTemplateInfo_003, TestSize.Level0)
{
    PinAuthExecutorHdi executorHdi(nullptr);
    UserAuth::TemplateInfo info = {};
    auto ret = executorHdi.GetTemplateInfo(0, info);
    EXPECT_TRUE(ret == IamResultCode::GENERAL_ERROR);
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_OnRegisterFinish_001, TestSize.Level0)
{
    for (const auto &pair : RESULT_CODE_MAP) {
        auto executorProxy = new (std::nothrow) PinHdi::MockIExecutor();
        ASSERT_TRUE(executorProxy != nullptr);
        EXPECT_CALL(*executorProxy, OnRegisterFinish(_, _, _))
            .Times(Exactly(1))
            .WillOnce(
                [&pair](const std::vector<uint64_t> &templateIdList, const std::vector<uint8_t> &frameworkPublicKey,
                    const std::vector<uint8_t> &extraInfo) { return pair.first; });
        PinAuthExecutorHdi executorHdi(executorProxy);
        UserAuth::TemplateInfo info = {};
        auto ret =
            executorHdi.OnRegisterFinish(std::vector<uint64_t>(), std::vector<uint8_t>(), std::vector<uint8_t>());
        EXPECT_TRUE(ret == pair.second);
    }
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_OnRegisterFinish_002, TestSize.Level0)
{
    PinAuthExecutorHdi executorHdi(nullptr);
    auto ret = executorHdi.OnRegisterFinish(std::vector<uint64_t>(), std::vector<uint8_t>(), std::vector<uint8_t>());
    EXPECT_TRUE(ret == IamResultCode::GENERAL_ERROR);
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_OnSetData_001, TestSize.Level0)
{
    for (const auto &pair : RESULT_CODE_MAP) {
        auto executorProxy = new (std::nothrow) PinHdi::MockIExecutor();
        ASSERT_TRUE(executorProxy != nullptr);
        EXPECT_CALL(*executorProxy, OnSetData(_, _, _))
            .Times(Exactly(1))
            .WillOnce([&pair](uint64_t scheduleId, uint64_t authSubType, const std::vector<uint8_t> &data)
                         { return pair.first; });
        PinAuthExecutorHdi executorHdi(executorProxy);
        UserAuth::TemplateInfo info = {};
        auto ret =
            executorHdi.OnSetData(0, 0, std::vector<uint8_t>());
        EXPECT_TRUE(ret == pair.second);
    }
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_OnSetData_002, TestSize.Level0)
{
    PinAuthExecutorHdi executorHdi(nullptr);
    auto ret = executorHdi.OnSetData(0, 0, std::vector<uint8_t>());
    EXPECT_TRUE(ret == IamResultCode::GENERAL_ERROR);
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_Enroll_001, TestSize.Level0)
{
    for (const auto &pair : RESULT_CODE_MAP) {
        auto executorProxy = new (std::nothrow) PinHdi::MockIExecutor();
        ASSERT_TRUE(executorProxy != nullptr);
        EXPECT_CALL(*executorProxy, Enroll(_, _, _))
            .Times(Exactly(1))
            .WillOnce([&pair](uint64_t scheduleId, const std::vector<uint8_t> &extraInfo,
                          const sptr<PinHdi::IExecutorCallback> &callbackObj) { return pair.first; });
        auto executorHdi = MakeShared<PinAuthExecutorHdi>(executorProxy);
        ASSERT_TRUE(executorHdi != nullptr);
        auto executeCallback = MakeShared<UserIam::UserAuth::MockIExecuteCallback>();
        ASSERT_TRUE(executeCallback != nullptr);
        auto ret = executorHdi->Enroll(0, 0, std::vector<uint8_t>(), executeCallback);
        EXPECT_TRUE(ret == pair.second);
    }
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_Enroll_002, TestSize.Level0)
{
    auto executorProxy = new (std::nothrow) PinHdi::MockIExecutor();
    ASSERT_TRUE(executorProxy != nullptr);
    auto executorHdi = MakeShared<PinAuthExecutorHdi>(executorProxy);
    ASSERT_TRUE(executorHdi != nullptr);
    auto ret = executorHdi->Enroll(0, 0, std::vector<uint8_t>(), nullptr);
    EXPECT_TRUE(ret == IamResultCode::GENERAL_ERROR);
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_Enroll_003, TestSize.Level0)
{
    auto executorHdi = MakeShared<PinAuthExecutorHdi>(nullptr);
    ASSERT_TRUE(executorHdi != nullptr);
    auto executeCallback = MakeShared<UserIam::UserAuth::MockIExecuteCallback>();
    ASSERT_TRUE(executeCallback != nullptr);
    auto ret = executorHdi->Enroll(0, 0, std::vector<uint8_t>(), executeCallback);
    EXPECT_TRUE(ret == IamResultCode::GENERAL_ERROR);
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_Authenticate_001, TestSize.Level0)
{
    for (const auto &pair : RESULT_CODE_MAP) {
        auto executorProxy = new (std::nothrow) PinHdi::MockIExecutor();
        ASSERT_TRUE(executorProxy != nullptr);
        EXPECT_CALL(*executorProxy, Authenticate(_, _, _, _)).Times(Exactly(1)).WillOnce([&pair](uint64_t scheduleId,
            uint64_t templateIdList, const std::vector<uint8_t> &extraInfo,
            const sptr<PinHdi::IExecutorCallback> &callbackObj) { return pair.first; });
        auto executorHdi = MakeShared<PinAuthExecutorHdi>(executorProxy);
        ASSERT_TRUE(executorHdi != nullptr);
        auto executeCallback = MakeShared<UserIam::UserAuth::MockIExecuteCallback>();
        ASSERT_TRUE(executeCallback != nullptr);
        const std::vector<uint64_t> templateIdList = {1, 2};
        auto ret = executorHdi->Authenticate(0, 0, templateIdList, std::vector<uint8_t>(), executeCallback);
        EXPECT_TRUE(ret == pair.second);
    }
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_Authenticate_002, TestSize.Level0)
{
    auto executorProxy = new (std::nothrow) PinHdi::MockIExecutor();
    ASSERT_TRUE(executorProxy != nullptr);
    auto executorHdi = MakeShared<PinAuthExecutorHdi>(executorProxy);
    auto ret = executorHdi->Authenticate(0, 0, std::vector<uint64_t>(), std::vector<uint8_t>(), nullptr);
    EXPECT_TRUE(ret == IamResultCode::GENERAL_ERROR);
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_Authenticate_003, TestSize.Level0)
{
    auto executorHdi = MakeShared<PinAuthExecutorHdi>(nullptr);
    auto executeCallback = MakeShared<UserIam::UserAuth::MockIExecuteCallback>();
    ASSERT_TRUE(executeCallback != nullptr);
    auto ret = executorHdi->Authenticate(0, 0, std::vector<uint64_t>(), std::vector<uint8_t>(), executeCallback);
    EXPECT_TRUE(ret == IamResultCode::GENERAL_ERROR);
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_Identify_001, TestSize.Level0)
{
    auto executorProxy = new (std::nothrow) PinHdi::MockIExecutor();
    ASSERT_TRUE(executorProxy != nullptr);
    PinAuthExecutorHdi executorHdi(executorProxy);
    auto ret = executorHdi.Identify(0, 0, std::vector<uint8_t>(), nullptr);
    EXPECT_TRUE(ret == IamResultCode::SUCCESS);
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_Delete_001, TestSize.Level0)
{
    for (const auto &pair : RESULT_CODE_MAP) {
        auto executorProxy = new (std::nothrow) PinHdi::MockIExecutor();
        ASSERT_TRUE(executorProxy != nullptr);
        EXPECT_CALL(*executorProxy, Delete(_))
            .Times(Exactly(1))
            .WillOnce([&pair](uint64_t templateId) { return pair.first; });
        auto executorHdi = MakeShared<PinAuthExecutorHdi>(executorProxy);
        ASSERT_TRUE(executorHdi != nullptr);
        const std::vector<uint64_t> templateIdList = {1, 2};
        auto ret = executorHdi->Delete(templateIdList);
        EXPECT_TRUE(ret == pair.second);
    }
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_Delete_002, TestSize.Level0)
{
    PinAuthExecutorHdi executorHdi(nullptr);
    auto ret = executorHdi.Delete(std::vector<uint64_t>());
    EXPECT_TRUE(ret == IamResultCode::GENERAL_ERROR);
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_Cancel_001, TestSize.Level0)
{
    for (const auto &pair : RESULT_CODE_MAP) {
        auto executorProxy = new (std::nothrow) PinHdi::MockIExecutor();
        ASSERT_TRUE(executorProxy != nullptr);
        EXPECT_CALL(*executorProxy, Cancel(_)).Times(Exactly(1)).WillOnce([&pair](uint64_t scheduleId) {
            return pair.first;
        });
        PinAuthExecutorHdi executorHdi(executorProxy);
        auto ret = executorHdi.Cancel(0);
        EXPECT_TRUE(ret == pair.second);
    }
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_Cancel_002, TestSize.Level0)
{
    PinAuthExecutorHdi executorHdi(nullptr);
    auto ret = executorHdi.Cancel(0);
    EXPECT_TRUE(ret == IamResultCode::GENERAL_ERROR);
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_SendCommand_001, TestSize.Level0)
{
    auto executorProxy = new (std::nothrow) PinHdi::MockIExecutor();
    ASSERT_TRUE(executorProxy != nullptr);
    PinAuthExecutorHdi executorHdi(executorProxy);
    auto ret = executorHdi.SendCommand(IamPropertyMode::PROPERTY_MODE_FREEZE, std::vector<uint8_t>(), nullptr);
    EXPECT_TRUE(ret == IamResultCode::SUCCESS);
}

} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
