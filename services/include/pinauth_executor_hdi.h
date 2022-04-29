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

#include <vector>
#include <map>
#include <v1_0/executor_proxy.h>
#include "framework_types.h"
#include "iexecute_callback.h"
#include "iauth_executor_hdi.h"

namespace OHOS {
namespace UserIAM {
namespace PinAuth {

namespace PinHDI = OHOS::HDI::Pinauth::V1_0;
class PinAuthExecutorHDI : public UserAuth::IAuthExecutorHDI {
public:
    PinAuthExecutorHDI(sptr<HDI::Pinauth::V1_0::IExecutor> executorProxy);
    virtual ~PinAuthExecutorHDI() = default;

    int GetExecutorInfo(UserIAM::ExecutorInfo& info);
    int GetTemplateInfo(uint64_t templateId, UserAuth::TemplateInfo& info);
    int OnRegisterFinish(const std::vector<uint64_t>& templateIdList, const std::vector<uint8_t>& frameworkPublicKey,
        const std::vector<uint8_t>& extraInfo);
    int Enroll(uint64_t scheduleId, uint64_t callerUid,const std::vector<uint8_t>& extraInfo,
        const std::shared_ptr<UserAuth::IExecuteCallback>& callbackObj);
    int Authenticate(uint64_t scheduleId, uint64_t callerUid, const std::vector<uint64_t>& templateIdList,
        const std::vector<uint8_t>& extraInfo, const std::shared_ptr<UserAuth::IExecuteCallback>& callbackObj);
    int Identify(uint64_t scheduleId, uint64_t callerUid, const std::vector<uint8_t>& extraInfo,
        const std::shared_ptr<UserAuth::IExecuteCallback>& callbackObj);
    int Delete(const std::vector<uint64_t>& templateIdList);
    int Cancel(uint64_t scheduleId);
    int SendCommand(UserAuth::CommandId commandId, const std::vector<uint8_t>& extraInfo,
        const std::shared_ptr<UserAuth::IExecuteCallback>& callbackObj);

protected:
    int MoveHDIExecutorInfo(PinHDI::ExecutorInfo &in, UserIAM::ExecutorInfo &out);
    int MoveHDITemplateInfo(PinHDI::TemplateInfo &in, UserAuth::TemplateInfo &out);
    int MapCommandId(const UserAuth::CommandId in, PinHDI::CommandId &out);
    int MapAuthType(const PinHDI::AuthType in, UserIAM::AuthType &out);
    int MapExecutorRole(const PinHDI::ExecutorRole in, UserIAM::ExecutorRole &out);
    int MapExecutorSecureLevel(const PinHDI::ExecutorSecureLevel in, UserIAM::ExecutorSecureLevel &out);
    sptr<HDI::Pinauth::V1_0::IExecutor> executorProxy_;
};

} // PinAuth
} // UserIAM
} // OHOS

#endif // PIN_AUTH_EXECUTOR_HDI_H