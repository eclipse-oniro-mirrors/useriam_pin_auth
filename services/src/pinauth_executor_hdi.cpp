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
#include "hdf_base.h"
#include "iam_logger.h"
#include "pinauth_executor_callback_hdi.h"

#define LOG_LABEL UserIAM::Common::LABEL_PIN_AUTH_SA

namespace OHOS {
namespace UserIAM {
namespace PinAuth {
PinAuthExecutorHdi::PinAuthExecutorHdi(sptr<HDI::PinAuth::V1_0::IExecutor> executorProxy)
    : executorProxy_(executorProxy) {};

UserIAM::ResultCode PinAuthExecutorHdi::GetExecutorInfo(UserIAM::ExecutorInfo &info)
{
    if (executorProxy_ == nullptr) {
        IAM_LOGE("executorProxy is null");
        return UserIAM::ResultCode::GENERAL_ERROR;
    }

    PinHdi::ExecutorInfo localInfo = { };
    int32_t status = executorProxy_->GetExecutorInfo(localInfo);
    UserIAM::ResultCode result = ConvertResultCode(status);
    if (result != UserIAM::ResultCode::SUCCESS) {
        IAM_LOGE("GetExecutorInfo fail ret=%{public}d", result);
        return result;
    }
    int32_t ret = MoveHdiExecutorInfo(localInfo, info);
    if (ret != UserIAM::ResultCode::SUCCESS) {
        IAM_LOGE("MoveHdiExecutorInfo fail ret=%{public}d", ret);
        return UserIAM::ResultCode::GENERAL_ERROR;
    }
    return UserIAM::ResultCode::SUCCESS;
}

UserIAM::ResultCode PinAuthExecutorHdi::GetTemplateInfo(uint64_t templateId, UserAuth::TemplateInfo &info)
{
    if (executorProxy_ == nullptr) {
        IAM_LOGE("executorProxy is null");
        return UserIAM::ResultCode::GENERAL_ERROR;
    }

    PinHdi::TemplateInfo localInfo = {};
    int32_t status = executorProxy_->GetTemplateInfo(templateId, localInfo);
    UserIAM::ResultCode result = ConvertResultCode(status);
    if (result != UserIAM::ResultCode::SUCCESS) {
        IAM_LOGE("GetTemplateInfo fail ret=%{public}d", result);
        return result;
    }
    int32_t ret = MoveHdiTemplateInfo(localInfo, info);
    if (ret != UserIAM::ResultCode::SUCCESS) {
        IAM_LOGE("MoveHdiTemplateInfo fail ret=%{public}d", ret);
        return UserIAM::ResultCode::GENERAL_ERROR;
    }
    return UserIAM::ResultCode::SUCCESS;
}

UserIAM::ResultCode PinAuthExecutorHdi::OnRegisterFinish(const std::vector<uint64_t> &templateIdList,
    const std::vector<uint8_t> &frameworkPublicKey, const std::vector<uint8_t> &extraInfo)
{
    if (executorProxy_ == nullptr) {
        IAM_LOGE("executorProxy is null");
        return UserIAM::ResultCode::GENERAL_ERROR;
    }
    IAM_LOGI("This process is not currently supported");
    return UserIAM::ResultCode::SUCCESS;
}

UserIAM::ResultCode PinAuthExecutorHdi::OnSetData(uint64_t scheduleId, uint64_t authSubType,
    const std::vector<uint8_t> &data)
{
    if (executorProxy_ == nullptr) {
        IAM_LOGE("executorProxy is null");
        return UserIAM::ResultCode::GENERAL_ERROR;
    }
    int32_t status = executorProxy_->OnSetData(scheduleId, authSubType, data);
    UserIAM::ResultCode result = ConvertResultCode(status);
    if (result != UserIAM::ResultCode::SUCCESS) {
        IAM_LOGE("OnRegisterFinish fail ret=%{public}d", status);
        return result;
    }
    return UserIAM::ResultCode::SUCCESS;
}

UserIAM::ResultCode PinAuthExecutorHdi::Enroll(uint64_t scheduleId, uint64_t callerUid,
    const std::vector<uint8_t> &extraInfo, const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj)
{
    if (executorProxy_ == nullptr) {
        IAM_LOGE("executorProxy is null");
        return UserIAM::ResultCode::GENERAL_ERROR;
    }
    int32_t status = executorProxy_->Enroll(scheduleId, extraInfo,
        sptr<PinHdi::IExecutorCallback>(new PinAuthExecutorCallbackHdi(callbackObj, shared_from_this(), callerUid)));
    UserIAM::ResultCode result = ConvertResultCode(status);
    if (result != UserIAM::ResultCode::SUCCESS) {
        IAM_LOGE("Enroll fail ret=%{public}d", result);
        return result;
    }
    return UserIAM::ResultCode::SUCCESS;
}

UserIAM::ResultCode PinAuthExecutorHdi::Authenticate(uint64_t scheduleId, uint64_t callerUid,
    const std::vector<uint64_t> &templateIdList, const std::vector<uint8_t> &extraInfo,
    const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj)
{
    if (executorProxy_ == nullptr) {
        IAM_LOGE("executorProxy is null");
        return UserIAM::ResultCode::GENERAL_ERROR;
    }
    int32_t status = executorProxy_->Authenticate(scheduleId, templateIdList[0], extraInfo,
        sptr<PinHdi::IExecutorCallback>(new PinAuthExecutorCallbackHdi(callbackObj, shared_from_this(), callerUid)));
    UserIAM::ResultCode result = ConvertResultCode(status);
    if (result != UserIAM::ResultCode::SUCCESS) {
        IAM_LOGE("Authenticate fail ret=%{public}d", result);
        return result;
    }
    return UserIAM::ResultCode::SUCCESS;
}

UserIAM::ResultCode PinAuthExecutorHdi::Identify(uint64_t scheduleId, uint64_t callerUid,
    const std::vector<uint8_t> &extraInfo, const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj)
{
    IAM_LOGI("Adaptor frame interface, temporarily useless");
    static_cast<void>(scheduleId);
    static_cast<void>(callerUid);
    static_cast<void>(extraInfo);
    static_cast<void>(callbackObj);
    return UserIAM::ResultCode::SUCCESS;
}

UserIAM::ResultCode PinAuthExecutorHdi::Delete(const std::vector<uint64_t> &templateIdList)
{
    if (executorProxy_ == nullptr) {
        IAM_LOGE("executorProxy is null");
        return UserIAM::ResultCode::GENERAL_ERROR;
    }
    int32_t status = executorProxy_->Delete(templateIdList[0]);
    UserIAM::ResultCode result = ConvertResultCode(status);
    if (result != UserIAM::ResultCode::SUCCESS) {
        IAM_LOGE("Delete fail ret=%{public}d", result);
        return result;
    }
    return UserIAM::ResultCode::SUCCESS;
}

UserIAM::ResultCode PinAuthExecutorHdi::Cancel(uint64_t scheduleId)
{
    if (executorProxy_ == nullptr) {
        IAM_LOGE("executorProxy is null");
        return UserIAM::ResultCode::GENERAL_ERROR;
    }
    int32_t status = executorProxy_->Cancel(scheduleId);
    UserIAM::ResultCode result = ConvertResultCode(status);
    if (result != UserIAM::ResultCode::SUCCESS) {
        IAM_LOGE("Cancel fail ret=%{public}d", result);
        return result;
    }
    return UserIAM::ResultCode::SUCCESS;
}

UserIAM::ResultCode PinAuthExecutorHdi::SendCommand(UserAuth::AuthPropertyMode commandId,
    const std::vector<uint8_t> &extraInfo, const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj)
{
    IAM_LOGI("Adaptor frame interface, temporarily useless");
    static_cast<void>(commandId);
    static_cast<void>(extraInfo);
    static_cast<void>(callbackObj);
    return UserIAM::ResultCode::SUCCESS;
}

UserIAM::ResultCode PinAuthExecutorHdi::MoveHdiExecutorInfo(PinHdi::ExecutorInfo &in, UserIAM::ExecutorInfo &out)
{
    out.executorId = static_cast<int32_t>(in.sensorId);
    out.executorType = in.executorType;
    int32_t ret = ConvertExecutorRole(in.executorRole, out.role);
    if (ret != UserIAM::ResultCode::SUCCESS) {
        IAM_LOGE("executorProxy is null");
        return UserIAM::ResultCode::GENERAL_ERROR;
    }
    ret = ConvertAuthType(in.authType, out.authType);
    if (ret != UserIAM::ResultCode::SUCCESS) {
        IAM_LOGE("ConvertAuthType fail ret=%{public}d", ret);
        return UserIAM::ResultCode::GENERAL_ERROR;
    }
    ret = ConvertExecutorSecureLevel(in.esl, out.esl);
    if (ret != UserIAM::ResultCode::SUCCESS) {
        IAM_LOGE("ConvertExecutorSecureLevel fail ret=%{public}d", ret);
        return UserIAM::ResultCode::GENERAL_ERROR;
    }
    in.publicKey.swap(out.publicKey);
    return UserIAM::ResultCode::SUCCESS;
}

UserIAM::ResultCode PinAuthExecutorHdi::MoveHdiTemplateInfo(PinHdi::TemplateInfo &in, UserAuth::TemplateInfo &out)
{
    out.executorType = in.executorType;
    out.freezingTime = in.freezingTime;
    out.remainTimes = in.remainTimes;
    in.extraInfo.swap(out.extraInfo);
    return UserIAM::ResultCode::SUCCESS;
}

UserIAM::ResultCode PinAuthExecutorHdi::ConvertCommandId(const UserAuth::AuthPropertyMode in, PinHdi::CommandId &out)
{
    IAM_LOGI("Adaptor frame interface, temporarily useless");
    static_cast<void>(in);
    static_cast<void>(out);
    return UserIAM::ResultCode::SUCCESS;
}

UserIAM::ResultCode PinAuthExecutorHdi::ConvertAuthType(const PinHdi::AuthType in, UserIAM::AuthType &out)
{
    static const std::map<PinHdi::AuthType, UserIAM::AuthType> data = {
        {PinHdi::PIN, UserIAM::AuthType::PIN},
    };
    if (data.count(in) == 0) {
        IAM_LOGE("authType %{public}d is invalid", in);
        return UserIAM::ResultCode::GENERAL_ERROR;
    }
    out = data.at(in);
    return UserIAM::ResultCode::SUCCESS;
}

UserIAM::ResultCode PinAuthExecutorHdi::ConvertExecutorRole(const PinHdi::ExecutorRole in, UserIAM::ExecutorRole &out)
{
    static const std::map<PinHdi::ExecutorRole, UserIAM::ExecutorRole> data = {
        { PinHdi::ExecutorRole::COLLECTOR, UserIAM::ExecutorRole::COLLECTOR },
        { PinHdi::ExecutorRole::VERIFIER, UserIAM::ExecutorRole::VERIFIER },
        { PinHdi::ExecutorRole::ALL_IN_ONE, UserIAM::ExecutorRole::ALL_IN_ONE},
    };
    if (data.count(in) == 0) {
        IAM_LOGE("executorRole %{public}d is invalid", in);
        return UserIAM::ResultCode::GENERAL_ERROR;
    }
    out = data.at(in);
    return UserIAM::ResultCode::SUCCESS;
}

UserIAM::ResultCode PinAuthExecutorHdi::ConvertExecutorSecureLevel(const PinHdi::ExecutorSecureLevel in,
    UserIAM::ExecutorSecureLevel &out)
{
    static const std::map<PinHdi::ExecutorSecureLevel, UserIAM::ExecutorSecureLevel> data = {
        { PinHdi::ExecutorSecureLevel::ESL0, UserIAM::ExecutorSecureLevel::ESL0 },
        { PinHdi::ExecutorSecureLevel::ESL1, UserIAM::ExecutorSecureLevel::ESL1 },
        { PinHdi::ExecutorSecureLevel::ESL2, UserIAM::ExecutorSecureLevel::ESL2 },
        { PinHdi::ExecutorSecureLevel::ESL3, UserIAM::ExecutorSecureLevel::ESL3 },
    };
    if (data.count(in) == 0) {
        IAM_LOGE("executorSecureLevel %{public}d is invalid", in);
        return UserIAM::ResultCode::GENERAL_ERROR;
    }
    out = data.at(in);
    return UserIAM::ResultCode::SUCCESS;
}

UserIAM::ResultCode PinAuthExecutorHdi::ConvertResultCode(const int32_t in)
{
    HDF_STATUS hdfIn = static_cast<HDF_STATUS>(in);
    static const std::map<HDF_STATUS, UserIAM::ResultCode> data = {
        {HDF_SUCCESS, UserIAM::ResultCode::SUCCESS},
        {HDF_FAILURE, UserIAM::ResultCode::FAIL},
        {HDF_ERR_TIMEOUT, UserIAM::ResultCode::TIMEOUT},
        {HDF_ERR_QUEUE_FULL, UserIAM::ResultCode::BUSY},
        {HDF_ERR_DEVICE_BUSY, UserIAM::ResultCode::BUSY},
    };

    UserIAM::ResultCode out;
    if (data.count(hdfIn) == 0) {
        out = UserIAM::ResultCode::GENERAL_ERROR;
    } else {
        out = data.at(hdfIn);
    }
    IAM_LOGE("covert hdi result code %{public}d to framework result code %{public}d", in, out);
    return out;
}
} // PinAuth
} // UserIAM
} // OHOS