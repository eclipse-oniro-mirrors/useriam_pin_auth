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

#include "pinauth_executor_hdi.h"
#include "pinauth_executor_callback_hdi.h"
#include "pinauth_log_wrapper.h"

namespace OHOS {
namespace UserIAM {
namespace PinAuth {
PinAuthExecutorHDI::PinAuthExecutorHDI(sptr<HDI::Pinauth::V1_0::IExecutor> executorProxy)
    : executorProxy_(executorProxy) {};

int PinAuthExecutorHDI::GetExecutorInfo(UserIAM::ExecutorInfo& info)
{
    if (executorProxy_ == nullptr) {
        PINAUTH_HILOGE(MODULE_SERVICE, "executorProxy is null");
        return FAIL;
    }

    PinHDI::ExecutorInfo localInfo = { 0 };
    int ret = executorProxy_->GetExecutorInfo(localInfo);
    if (ret != SUCCESS) {
        PINAUTH_HILOGE(MODULE_SERVICE, "GetExecutorInfo fail ret=%{public}d", ret);
        return ret;
    }
    ret = MoveHDIExecutorInfo(localInfo, info);
    if (ret != SUCCESS) {
        PINAUTH_HILOGE(MODULE_SERVICE, "MoveHDIExecutorInfo fail ret=%{public}d", ret);
        return FAIL;
    }

    return SUCCESS;
}

int PinAuthExecutorHDI::GetTemplateInfo(uint64_t templateId, UserAuth::TemplateInfo& info)
{
    if (executorProxy_ == nullptr) {
        PINAUTH_HILOGE(MODULE_SERVICE, "executorProxy is null");
        return FAIL;
    }
    PinHDI::TemplateInfo localInfo = { 0 };
    int ret = executorProxy_->GetTemplateInfo(templateId, localInfo);
    if (ret != SUCCESS) {
        PINAUTH_HILOGE(MODULE_SERVICE, "GetTemplateInfo fail ret=%{public}d", ret);
        return FAIL;
    }
    ret = MoveHDITemplateInfo(localInfo, info);
    if (ret != SUCCESS) {
        PINAUTH_HILOGE(MODULE_SERVICE, "MoveHDITemplateInfo fail ret=%{public}d", ret);
        return FAIL;
    }
    return SUCCESS;
}

int PinAuthExecutorHDI::OnRegisterFinish(const std::vector<uint64_t>& templateIdList,
    const std::vector<uint8_t>& frameworkPublicKey, const std::vector<uint8_t>& extraInfo)
{
    if (executorProxy_ == nullptr) {
        PINAUTH_HILOGE(MODULE_SERVICE, "executorProxy is null");
        return FAIL;
    }
    int ret = executorProxy_->OnRegisterFinish(templateIdList, frameworkPublicKey, extraInfo);
    if (ret != SUCCESS) {
        PINAUTH_HILOGE(MODULE_SERVICE, "OnRegisterFinish fail ret=%{public}d", ret);
        return ret;
    }
    return SUCCESS;
}

int PinAuthExecutorHDI::Enroll(uint64_t scheduleId, uint64_t callerUid, const std::vector<uint8_t>& extraInfo,
    const std::shared_ptr<UserAuth::IExecuteCallback>& callbackObj)
{
    if (executorProxy_ == nullptr) {
        PINAUTH_HILOGE(MODULE_SERVICE, "executorProxy is null");
        return FAIL;
    }
    int ret = executorProxy_->Enroll(scheduleId, extraInfo,
        sptr<PinHDI::IExecutorCallback>(new PinAuthExecutorCallbackHDI(callbackObj, callerUid)));
    if (ret != SUCCESS) {
        PINAUTH_HILOGE(MODULE_SERVICE, "Enroll fail ret=%{public}d", ret);
        return ret;
    }
    return SUCCESS;
}

int PinAuthExecutorHDI::Authenticate(uint64_t scheduleId, uint64_t callerUid,
    const std::vector<uint64_t>& templateIdList, const std::vector<uint8_t>& extraInfo,
    const std::shared_ptr<UserAuth::IExecuteCallback>& callbackObj)
{
    if (executorProxy_ == nullptr) {
        PINAUTH_HILOGE(MODULE_SERVICE, "executorProxy is null");
        return FAIL;
    }
    int ret = executorProxy_->Authenticate(scheduleId, templateIdList[0], extraInfo,
        sptr<PinHDI::IExecutorCallback>(new PinAuthExecutorCallbackHDI(callbackObj, callerUid)));
    if (ret != SUCCESS) {
        PINAUTH_HILOGE(MODULE_SERVICE, "Authenticate fail ret=%{public}d", ret);
        return ret;
    }
    return SUCCESS;
}

int PinAuthExecutorHDI::Identify(uint64_t scheduleId, uint64_t callerUid, const std::vector<uint8_t>& extraInfo,
    const std::shared_ptr<UserAuth::IExecuteCallback>& callbackObj)
{
    PINAUTH_HILOGE(MODULE_SERVICE, "Adaptor frame interface, temporarily useless");
    return FAIL;
}

int PinAuthExecutorHDI::Delete(const std::vector<uint64_t>& templateIdList)
{
    if (executorProxy_ == nullptr) {
        PINAUTH_HILOGE(MODULE_SERVICE, "executorProxy is null");
        return FAIL;
    }
    int ret = executorProxy_->Delete(templateIdList[0]);
    if (ret != SUCCESS) {
        PINAUTH_HILOGE(MODULE_SERVICE, "Delete fail ret=%{public}d", ret);
        return ret;
    }
    return SUCCESS;
}

int PinAuthExecutorHDI::Cancel(uint64_t scheduleId)
{
    if (executorProxy_ == nullptr) {
        PINAUTH_HILOGE(MODULE_SERVICE, "executorProxy is null");
        return FAIL;
    }
    int ret = executorProxy_->Cancel(scheduleId);
    if (ret != SUCCESS) {
        PINAUTH_HILOGE(MODULE_SERVICE, "Cancel fail ret=%{public}d", ret);
        return ret;
    }
    return SUCCESS;
}

int PinAuthExecutorHDI::SendCommand(UserAuth::CommandId commandId, const std::vector<uint8_t>& extraInfo,
    const std::shared_ptr<UserAuth::IExecuteCallback>& callbackObj)
{
     if (executorProxy_ == nullptr) {
        PINAUTH_HILOGE(MODULE_SERVICE, "executorProxy is null");
        return FAIL;
    }

    return FAIL;
}

int PinAuthExecutorHDI::MoveHDIExecutorInfo(PinHDI::ExecutorInfo &in, UserIAM::ExecutorInfo &out)
{
    out.executorId = static_cast<int32_t>(in.sensorId);
    out.executorType = in.executorType;
    int ret = MapExecutorRole(in.executorRole, out.role);
    if (ret != SUCCESS) {
        PINAUTH_HILOGE(MODULE_SERVICE, "executorProxy is null");
        return FAIL;
    }
    ret = MapAuthType(in.authType, out.authType);
    if (ret != SUCCESS) {
        PINAUTH_HILOGE(MODULE_SERVICE, "MapAuthType fail ret=%{public}d", ret);
        return FAIL;
    }
    ret = MapExecutorSecureLevel(in.esl, out.esl);
    if (ret != SUCCESS) {
        PINAUTH_HILOGE(MODULE_SERVICE, "MapExecutorSecureLevel fail ret=%{public}d", ret);
        return FAIL;
    }
    in.publicKey.swap(out.publicKey);

    return SUCCESS;
}

int PinAuthExecutorHDI::MoveHDITemplateInfo(PinHDI::TemplateInfo &in, UserAuth::TemplateInfo &out)
{
    out.executorType = in.executorType;
    out.freezingTime = in.freezingTime;
    out.remainTimes = in.remainTimes;
    in.extraInfo.swap(out.extraInfo);
    return SUCCESS;
}

int PinAuthExecutorHDI::MapCommandId(const UserAuth::CommandId in, PinHDI::CommandId &out)
{
    PINAUTH_HILOGE(MODULE_SERVICE, "The reserved interface is not implemented");
    return FAIL;
}

int PinAuthExecutorHDI::MapAuthType(const PinHDI::AuthType in, UserIAM::AuthType &out)
{
    static const std::map<PinHDI::AuthType, UserIAM::AuthType> data = {
        { PinHDI::PIN, UserIAM::AuthType::PIN },
    };
    if (data.count(in) == 0) {
        PINAUTH_HILOGE(MODULE_SERVICE, "authType=%{public}d not found", in);
        return FAIL;
    }
    out = data.at(in);
    return SUCCESS;
}

int PinAuthExecutorHDI::MapExecutorRole(const PinHDI::ExecutorRole in, UserIAM::ExecutorRole &out)
{
    static const std::map<PinHDI::ExecutorRole, UserIAM::ExecutorRole> data = {
        { PinHDI::ExecutorRole::COLLECTOR, UserIAM::ExecutorRole::COLLECTOR },
        { PinHDI::ExecutorRole::VERIFIER, UserIAM::ExecutorRole::VERIFIER },
        { PinHDI::ExecutorRole::ALL_IN_ONE, UserIAM::ExecutorRole::ALL_IN_ONE},
    };
    if (data.count(in) == 0) {
        PINAUTH_HILOGE(MODULE_SERVICE, "executorRole=%{public}d not found", in);
        return FAIL;
    }
    out = data.at(in);
    return SUCCESS;
}

int PinAuthExecutorHDI::MapExecutorSecureLevel(const PinHDI::ExecutorSecureLevel in,
    UserIAM::ExecutorSecureLevel &out)
{
    static const std::map<PinHDI::ExecutorSecureLevel, UserIAM::ExecutorSecureLevel> data = {
        { PinHDI::ExecutorSecureLevel::ESL0, UserIAM::ExecutorSecureLevel::ESL0 },
        { PinHDI::ExecutorSecureLevel::ESL1, UserIAM::ExecutorSecureLevel::ESL1 },
        { PinHDI::ExecutorSecureLevel::ESL2, UserIAM::ExecutorSecureLevel::ESL2 },
        { PinHDI::ExecutorSecureLevel::ESL3, UserIAM::ExecutorSecureLevel::ESL3 },
    };
    if (data.count(in) == 0) {
        PINAUTH_HILOGE(MODULE_SERVICE, "executorSecureLevel=%{public}d not found", in);
        return FAIL;
    }
    out = data.at(in);
    return SUCCESS;
}

} // PinAuth
} // UserIAM
} // OHOS