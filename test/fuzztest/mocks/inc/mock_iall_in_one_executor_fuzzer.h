/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef MOCK_IALL_IN_ONE_EXECUTOR_FUZZER_H
#define MOCK_IALL_IN_ONE_EXECUTOR_FUZZER_H

#include "iam_common_defines.h"
#include "pin_auth_hdi.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
using namespace OHOS;
using namespace OHOS::HDI::PinAuth::V2_1;
class MockIAllInOneExecutorFuzzer : public IAllInOneExecutor {
public:
    virtual ~MockIAllInOneExecutorFuzzer() = default;
    int32_t GetExecutorInfo(ExecutorInfo& executorInfo) override
    {
        executorInfo.executorRole = ExecutorRole::ALL_IN_ONE;
        executorInfo.authType = AuthType::PIN;
        executorInfo.esl = ExecutorSecureLevel::ESL3;
        return isTrueTest();
    }

    int32_t OnRegisterFinish(const std::vector<uint64_t>& templateIdList,
         const std::vector<uint8_t>& frameworkPublicKey, const std::vector<uint8_t>& extraInfo) override
    {
        return isTrueTest();
    }

    int32_t Cancel(uint64_t scheduleId) override
    {
        return isTrueTest();
    }

    int32_t SendMessage(uint64_t scheduleId, int32_t srcRole, const std::vector<uint8_t>& msg) override
    {
        return isTrueTest();
    }

    int32_t SetData(uint64_t scheduleId, uint64_t authSubType, const std::vector<uint8_t>& data,
         int32_t resultCode) override
    {
        return isTrueTest();
    }

    int32_t Enroll(uint64_t scheduleId, const std::vector<uint8_t>& extraInfo,
         const sptr<IExecutorCallback>& callbackObj) override
    {
        return isTrueTest();
    }

    int32_t Authenticate(uint64_t scheduleId, const std::vector<uint64_t>& templateIdList,
         const std::vector<uint8_t>& extraInfo, const sptr<IExecutorCallback>& callbackObj) override
    {
        return isTrueTest();
    }

    int32_t Delete(uint64_t templateId) override
    {
        return isTrueTest();
    }

    int32_t GetProperty(const std::vector<uint64_t>& templateIdList, const std::vector<int32_t>& propertyTypes,
         Property& property) override
    {
        return isTrueTest();
    }
    int32_t SendCommand(int32_t commandId, const std::vector<uint8_t> &extraInfo,
        const sptr<IExecutorCallback> &callbackObj) override
    {
        return isTrueTest();
    }
private:
    bool isTrue_ = false;
    int32_t isTrueTest();
};

int32_t MockIAllInOneExecutorFuzzer::isTrueTest()
{
    isTrue_ = !isTrue_;
    return isTrue_ ? UserAuth::ResultCode::SUCCESS : UserAuth::ResultCode::FAIL;
}

} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS

#endif // MOCK_IALL_IN_ONE_EXECUTOR_FUZZER_H