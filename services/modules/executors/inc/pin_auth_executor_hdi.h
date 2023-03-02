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

#ifndef PIN_AUTH_EXECUTOR_HDI_H
#define PIN_AUTH_EXECUTOR_HDI_H

#include <cstdint>
#include <map>
#include <v1_0/iexecutor.h>
#include <vector>
#include "iam_executor_framework_types.h"
#include "iam_executor_iauth_executor_hdi.h"
#include "iam_executor_iexecute_callback.h"
#include "nocopyable.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
namespace PinHdi = OHOS::HDI::PinAuth::V1_0;
class PinAuthExecutorHdi : public std::enable_shared_from_this<PinAuthExecutorHdi>,
    public UserAuth::IAuthExecutorHdi, public NoCopyable {
public:
    explicit PinAuthExecutorHdi(const sptr<HDI::PinAuth::V1_0::IExecutor> &executorProxy);
    ~PinAuthExecutorHdi() override = default;

    UserAuth::ResultCode GetExecutorInfo(UserAuth::ExecutorInfo &info) override;
    UserAuth::ResultCode GetTemplateInfo(uint64_t templateId, UserAuth::TemplateInfo &info) override;
    UserAuth::ResultCode OnRegisterFinish(const std::vector<uint64_t> &templateIdList,
        const std::vector<uint8_t> &frameworkPublicKey, const std::vector<uint8_t> &extraInfo) override;
    UserAuth::ResultCode Enroll(uint64_t scheduleId, uint32_t tokenId, const std::vector<uint8_t> &extraInfo,
        const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) override;
    UserAuth::ResultCode Authenticate(uint64_t scheduleId, uint32_t tokenId,
        const std::vector<uint64_t> &templateIdList, const std::vector<uint8_t> &extraInfo,
        const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) override;
    UserAuth::ResultCode OnSetData(uint64_t scheduleId, uint64_t authSubType, const std::vector<uint8_t>& data);
    UserAuth::ResultCode Identify(uint64_t scheduleId, uint32_t tokenId, const std::vector<uint8_t> &extraInfo,
        const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) override;
    UserAuth::ResultCode Delete(const std::vector<uint64_t> &templateIdList) override;
    UserAuth::ResultCode Cancel(uint64_t scheduleId) override;
    UserAuth::ResultCode SendCommand(UserAuth::PropertyMode commandId, const std::vector<uint8_t> &extraInfo,
        const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) override;

private:
    UserAuth::ResultCode MoveHdiExecutorInfo(PinHdi::ExecutorInfo &in, UserAuth::ExecutorInfo &out);
    UserAuth::ResultCode MoveHdiTemplateInfo(PinHdi::TemplateInfo &in, UserAuth::TemplateInfo &out);
    UserAuth::ResultCode ConvertCommandId(const UserAuth::PropertyMode in, PinHdi::CommandId &out);
    UserAuth::ResultCode ConvertAuthType(const PinHdi::AuthType in, UserAuth::AuthType &out);
    UserAuth::ResultCode ConvertExecutorRole(const PinHdi::ExecutorRole in, UserAuth::ExecutorRole &out);
    UserAuth::ResultCode ConvertExecutorSecureLevel(const PinHdi::ExecutorSecureLevel in,
        UserAuth::ExecutorSecureLevel &out);
    UserAuth::ResultCode ConvertResultCode(const int32_t in);
    sptr<PinHdi::IExecutor> executorProxy_ {nullptr};
};
} // PinAuth
} // UserIam
} // OHOS

#endif // PIN_AUTH_EXECUTOR_HDI_H