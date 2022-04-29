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
#include <v1_0/executor_proxy.h>
#include <vector>
#include "framework_types.h"
#include "iauth_executor_hdi.h"
#include "iexecute_callback.h"
#include "nocopyable.h"

namespace OHOS {
namespace UserIAM {
namespace PinAuth {
namespace PinHdi = OHOS::HDI::PinAuth::V1_0;
class PinAuthExecutorHdi : public std::enable_shared_from_this<PinAuthExecutorHdi>, public UserAuth::IAuthExecutorHdi,
    public NoCopyable {
public:
    explicit PinAuthExecutorHdi(sptr<HDI::PinAuth::V1_0::IExecutor> executorProxy);
    virtual ~PinAuthExecutorHdi() = default;

    UserIAM::ResultCode GetExecutorInfo(UserIAM::ExecutorInfo &info);
    UserIAM::ResultCode GetTemplateInfo(uint64_t templateId, UserAuth::TemplateInfo &info);
    UserIAM::ResultCode OnRegisterFinish(const std::vector<uint64_t> &templateIdList,
        const std::vector<uint8_t> &frameworkPublicKey, const std::vector<uint8_t> &extraInfo);
    UserIAM::ResultCode Enroll(uint64_t scheduleId, uint64_t callerUid, const std::vector<uint8_t> &extraInfo,
        const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj);
    UserIAM::ResultCode Authenticate(uint64_t scheduleId, uint64_t callerUid,
        const std::vector<uint64_t> &templateIdList, const std::vector<uint8_t> &extraInfo,
        const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj);
    UserIAM::ResultCode OnSetData(uint64_t scheduleId, uint64_t authSubType, const std::vector<uint8_t>& data);
    UserIAM::ResultCode Identify(uint64_t scheduleId, uint64_t callerUid, const std::vector<uint8_t> &extraInfo,
        const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj);
    UserIAM::ResultCode Delete(const std::vector<uint64_t> &templateIdList);
    UserIAM::ResultCode Cancel(uint64_t scheduleId);
    UserIAM::ResultCode SendCommand(UserAuth::AuthPropertyMode commandId, const std::vector<uint8_t> &extraInfo,
        const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj);

private:
    UserIAM::ResultCode MoveHdiExecutorInfo(PinHdi::ExecutorInfo &in, UserIAM::ExecutorInfo &out);
    UserIAM::ResultCode MoveHdiTemplateInfo(PinHdi::TemplateInfo &in, UserAuth::TemplateInfo &out);
    UserIAM::ResultCode ConvertCommandId(const UserAuth::AuthPropertyMode in, PinHdi::CommandId &out);
    UserIAM::ResultCode ConvertAuthType(const PinHdi::AuthType in, UserIAM::AuthType &out);
    UserIAM::ResultCode ConvertExecutorRole(const PinHdi::ExecutorRole in, UserIAM::ExecutorRole &out);
    UserIAM::ResultCode ConvertExecutorSecureLevel(
        const PinHdi::ExecutorSecureLevel in, UserIAM::ExecutorSecureLevel &out);
    UserIAM::ResultCode ConvertResultCode(const int32_t in);
    sptr<PinHdi::IExecutor> executorProxy_;
};
} // PinAuth
} // UserIAM
} // OHOS

#endif // PIN_AUTH_EXECUTOR_HDI_H