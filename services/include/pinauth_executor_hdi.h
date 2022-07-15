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

    UserIam::UserAuth::ResultCode GetExecutorInfo(UserIam::UserAuth::ExecutorInfo &info);
    UserIam::UserAuth::ResultCode GetTemplateInfo(uint64_t templateId, UserAuth::TemplateInfo &info);
    UserIam::UserAuth::ResultCode OnRegisterFinish(const std::vector<uint64_t> &templateIdList,
        const std::vector<uint8_t> &frameworkPublicKey, const std::vector<uint8_t> &extraInfo);
    UserIam::UserAuth::ResultCode Enroll(uint64_t scheduleId, uint32_t tokenId, const std::vector<uint8_t> &extraInfo,
        const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj);
    UserIam::UserAuth::ResultCode Authenticate(uint64_t scheduleId, uint32_t tokenId,
        const std::vector<uint64_t> &templateIdList, const std::vector<uint8_t> &extraInfo,
        const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj);
    UserIam::UserAuth::ResultCode OnSetData(uint64_t scheduleId, uint64_t authSubType, const std::vector<uint8_t>& data);
    UserIam::UserAuth::ResultCode Identify(uint64_t scheduleId, uint32_t tokenId, const std::vector<uint8_t> &extraInfo,
        const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj);
    UserIam::UserAuth::ResultCode Delete(const std::vector<uint64_t> &templateIdList);
    UserIam::UserAuth::ResultCode Cancel(uint64_t scheduleId);
    UserIam::UserAuth::ResultCode SendCommand(UserIam::UserAuth::PropertyMode commandId, const std::vector<uint8_t> &extraInfo,
        const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj);

private:
    UserIam::UserAuth::ResultCode MoveHdiExecutorInfo(PinHdi::ExecutorInfo &in, UserIam::UserAuth::ExecutorInfo &out);
    UserIam::UserAuth::ResultCode MoveHdiTemplateInfo(PinHdi::TemplateInfo &in, UserAuth::TemplateInfo &out);
    UserIam::UserAuth::ResultCode ConvertCommandId(const UserIam::UserAuth::PropertyMode in, PinHdi::CommandId &out);
    UserIam::UserAuth::ResultCode ConvertAuthType(const PinHdi::AuthType in, UserIam::UserAuth::AuthType &out);
    UserIam::UserAuth::ResultCode ConvertExecutorRole(const PinHdi::ExecutorRole in, UserIam::UserAuth::ExecutorRole &out);
    UserIam::UserAuth::ResultCode ConvertExecutorSecureLevel(
        const PinHdi::ExecutorSecureLevel in, UserIam::UserAuth::ExecutorSecureLevel &out);
    UserIam::UserAuth::ResultCode ConvertResultCode(const int32_t in);
    sptr<PinHdi::IExecutor> executorProxy_;
};
} // PinAuth
} // UserIAM
} // OHOS

#endif // PIN_AUTH_EXECUTOR_HDI_H