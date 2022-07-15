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
#include "iam_defines.h"
#include "hisysevent.h"
#include "pinauth_executor_callback_hdi.h"

#define LOG_LABEL UserIAM::Common::LABEL_PIN_AUTH_SA

namespace OHOS {
namespace UserIAM {
namespace PinAuth {
using namespace OHOS::UserIam::UserAuth;
PinAuthExecutorHdi::PinAuthExecutorHdi(sptr<HDI::PinAuth::V1_0::IExecutor> executorProxy)
    : executorProxy_(executorProxy) {};

UserIam::UserAuth::ResultCode PinAuthExecutorHdi::GetExecutorInfo(UserIam::UserAuth::ExecutorInfo &info)
{
    if (executorProxy_ == nullptr) {
        IAM_LOGE("executorProxy is null");
        return UserIam::UserAuth::ResultCode::GENERAL_ERROR;
    }

    PinHdi::ExecutorInfo localInfo = { };
    int32_t status = executorProxy_->GetExecutorInfo(localInfo);
    UserIam::UserAuth::ResultCode result = ConvertResultCode(status);
    if (result != UserIam::UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("GetExecutorInfo fail ret=%{public}d", result);
        return result;
    }
    int32_t ret = MoveHdiExecutorInfo(localInfo, info);
    if (ret != UserIam::UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("MoveHdiExecutorInfo fail ret=%{public}d", ret);
        return UserIam::UserAuth::ResultCode::GENERAL_ERROR;
    }
    return UserIam::UserAuth::ResultCode::SUCCESS;
}

UserIam::UserAuth::ResultCode PinAuthExecutorHdi::GetTemplateInfo(uint64_t templateId, UserAuth::TemplateInfo &info)
{
    if (executorProxy_ == nullptr) {
        IAM_LOGE("executorProxy is null");
        return UserIam::UserAuth::ResultCode::GENERAL_ERROR;
    }

    PinHdi::TemplateInfo localInfo = {};
    int32_t status = executorProxy_->GetTemplateInfo(templateId, localInfo);
    UserIam::UserAuth::ResultCode result = ConvertResultCode(status);
    if (result != UserIam::UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("GetTemplateInfo fail ret=%{public}d", result);
        return result;
    }
    int32_t ret = MoveHdiTemplateInfo(localInfo, info);
    if (ret != UserIam::UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("MoveHdiTemplateInfo fail ret=%{public}d", ret);
        return UserIam::UserAuth::ResultCode::GENERAL_ERROR;
    }
    return UserIam::UserAuth::ResultCode::SUCCESS;
}

UserIam::UserAuth::ResultCode PinAuthExecutorHdi::OnRegisterFinish(const std::vector<uint64_t> &templateIdList,
    const std::vector<uint8_t> &frameworkPublicKey, const std::vector<uint8_t> &extraInfo)
{
    if (executorProxy_ == nullptr) {
        IAM_LOGE("executorProxy is null");
        return UserIam::UserAuth::ResultCode::GENERAL_ERROR;
    }
    int32_t status = executorProxy_->OnRegisterFinish(templateIdList, frameworkPublicKey, extraInfo);
    UserIam::UserAuth::ResultCode result = ConvertResultCode(status);
    if (result != UserIam::UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("OnRegisterFinish fail result %{public}d", status);
        return result;
    }

    OHOS::HiviewDFX::HiSysEvent::Write("USERIAM_PIN", "USERIAM_TEMPLATE_CHANGE",
        OHOS::HiviewDFX::HiSysEvent::EventType::SECURITY, "EXECUTOR_TYPE", PIN,
        "CHANGE_TYPE", UserIam::UserAuth::TRACE_DELETE_CREDENTIAL, "TRIGGER_REASON", "Reconciliation");
    return UserIam::UserAuth::ResultCode::SUCCESS;
}

UserIam::UserAuth::ResultCode PinAuthExecutorHdi::OnSetData(uint64_t scheduleId, uint64_t authSubType,
    const std::vector<uint8_t> &data)
{
    if (executorProxy_ == nullptr) {
        IAM_LOGE("executorProxy is null");
        return UserIam::UserAuth::ResultCode::GENERAL_ERROR;
    }
    int32_t status = executorProxy_->OnSetData(scheduleId, authSubType, data);
    UserIam::UserAuth::ResultCode result = ConvertResultCode(status);
    if (result != UserIam::UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("OnRegisterFinish fail ret=%{public}d", status);
        return result;
    }
    return UserIam::UserAuth::ResultCode::SUCCESS;
}

UserIam::UserAuth::ResultCode PinAuthExecutorHdi::Enroll(uint64_t scheduleId, uint32_t tokenId,
    const std::vector<uint8_t> &extraInfo, const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj)
{
    if (executorProxy_ == nullptr) {
        IAM_LOGE("executorProxy is null");
        return UserIam::UserAuth::ResultCode::GENERAL_ERROR;
    }
    auto callback = sptr<PinHdi::IExecutorCallback>(new (std::nothrow) PinAuthExecutorCallbackHdi(callbackObj,
        shared_from_this(), tokenId));
    if (callback == nullptr) {
        IAM_LOGE("callback is null");
        return UserIam::UserAuth::ResultCode::GENERAL_ERROR;
    }
    int32_t status = executorProxy_->Enroll(scheduleId, extraInfo, callback);
    UserIam::UserAuth::ResultCode result = ConvertResultCode(status);
    if (result != UserIam::UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("Enroll fail ret=%{public}d", result);
        return result;
    }
    return UserIam::UserAuth::ResultCode::SUCCESS;
}

UserIam::UserAuth::ResultCode PinAuthExecutorHdi::Authenticate(uint64_t scheduleId, uint32_t tokenId,
    const std::vector<uint64_t> &templateIdList, const std::vector<uint8_t> &extraInfo,
    const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj)
{
    if (executorProxy_ == nullptr) {
        IAM_LOGE("executorProxy is null");
        return UserIam::UserAuth::ResultCode::GENERAL_ERROR;
    }
    auto callback = sptr<PinHdi::IExecutorCallback>(new (std::nothrow) PinAuthExecutorCallbackHdi(callbackObj,
        shared_from_this(), tokenId));
    if (callback == nullptr) {
        IAM_LOGE("callback is null");
        return UserIam::UserAuth::ResultCode::GENERAL_ERROR;
    }
    if (templateIdList.size() == 0) {
        IAM_LOGE("Error param");
        return UserIam::UserAuth::ResultCode::GENERAL_ERROR;
    }
    int32_t status = executorProxy_->Authenticate(scheduleId, templateIdList[0], extraInfo, callback);
    UserIam::UserAuth::ResultCode result = ConvertResultCode(status);
    if (result != UserIam::UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("Authenticate fail ret=%{public}d", result);
        return result;
    }
    return UserIam::UserAuth::ResultCode::SUCCESS;
}

UserIam::UserAuth::ResultCode PinAuthExecutorHdi::Identify(uint64_t scheduleId, uint32_t tokenId,
    const std::vector<uint8_t> &extraInfo, const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj)
{
    IAM_LOGI("Adaptor frame interface, temporarily useless");
    static_cast<void>(scheduleId);
    static_cast<void>(tokenId);
    static_cast<void>(extraInfo);
    static_cast<void>(callbackObj);
    return UserIam::UserAuth::ResultCode::SUCCESS;
}

UserIam::UserAuth::ResultCode PinAuthExecutorHdi::Delete(const std::vector<uint64_t> &templateIdList)
{
    if (executorProxy_ == nullptr) {
        IAM_LOGE("executorProxy is null");
        return UserIam::UserAuth::ResultCode::GENERAL_ERROR;
    }
    int32_t status = executorProxy_->Delete(templateIdList[0]);
    UserIam::UserAuth::ResultCode result = ConvertResultCode(status);
    if (result != UserIam::UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("Delete fail ret=%{public}d", result);
        return result;
    }
    return UserIam::UserAuth::ResultCode::SUCCESS;
}

UserIam::UserAuth::ResultCode PinAuthExecutorHdi::Cancel(uint64_t scheduleId)
{
    if (executorProxy_ == nullptr) {
        IAM_LOGE("executorProxy is null");
        return UserIam::UserAuth::ResultCode::GENERAL_ERROR;
    }
    int32_t status = executorProxy_->Cancel(scheduleId);
    UserIam::UserAuth::ResultCode result = ConvertResultCode(status);
    if (result != UserIam::UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("Cancel fail ret=%{public}d", result);
        return result;
    }
    return UserIam::UserAuth::ResultCode::SUCCESS;
}

UserIam::UserAuth::ResultCode PinAuthExecutorHdi::SendCommand(UserIam::UserAuth::PropertyMode commandId,
    const std::vector<uint8_t> &extraInfo, const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj)
{
    IAM_LOGI("Adaptor frame interface, temporarily useless");
    static_cast<void>(commandId);
    static_cast<void>(extraInfo);
    static_cast<void>(callbackObj);
    return UserIam::UserAuth::ResultCode::SUCCESS;
}

UserIam::UserAuth::ResultCode PinAuthExecutorHdi::MoveHdiExecutorInfo(PinHdi::ExecutorInfo &in, UserIam::UserAuth::ExecutorInfo &out)
{
    out.executorSensorHint = static_cast<int32_t>(in.sensorId);
    out.executorMatcher = static_cast<int32_t>(in.executorType);
    int32_t ret = ConvertExecutorRole(in.executorRole, out.executorRole);
    if (ret != UserIam::UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("executorProxy is null");
        return UserIam::UserAuth::ResultCode::GENERAL_ERROR;
    }
    ret = ConvertAuthType(in.authType, out.authType);
    if (ret != UserIam::UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("ConvertAuthType fail ret=%{public}d", ret);
        return UserIam::UserAuth::ResultCode::GENERAL_ERROR;
    }
    ret = ConvertExecutorSecureLevel(in.esl, out.esl);
    if (ret != UserIam::UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("ConvertExecutorSecureLevel fail ret=%{public}d", ret);
        return UserIam::UserAuth::ResultCode::GENERAL_ERROR;
    }
    in.publicKey.swap(out.publicKey);
    return UserIam::UserAuth::ResultCode::SUCCESS;
}

UserIam::UserAuth::ResultCode PinAuthExecutorHdi::MoveHdiTemplateInfo(PinHdi::TemplateInfo &in, UserAuth::TemplateInfo &out)
{
    out.executorType = in.executorType;
    out.freezingTime = in.freezingTime;
    out.remainTimes = in.remainTimes;
    in.extraInfo.swap(out.extraInfo);
    return UserIam::UserAuth::ResultCode::SUCCESS;
}

UserIam::UserAuth::ResultCode PinAuthExecutorHdi::ConvertCommandId(const UserIam::UserAuth::PropertyMode in, PinHdi::CommandId &out)
{
    IAM_LOGI("Adaptor frame interface, temporarily useless");
    static_cast<void>(in);
    static_cast<void>(out);
    return UserIam::UserAuth::ResultCode::SUCCESS;
}

UserIam::UserAuth::ResultCode PinAuthExecutorHdi::ConvertAuthType(const PinHdi::AuthType in, UserIam::UserAuth::AuthType &out)
{
    static const std::map<PinHdi::AuthType, UserIam::UserAuth::AuthType> data = {
        {PinHdi::PIN, UserIam::UserAuth::AuthType::PIN},
    };
    if (data.count(in) == 0) {
        IAM_LOGE("authType %{public}d is invalid", in);
        return UserIam::UserAuth::ResultCode::GENERAL_ERROR;
    }
    out = data.at(in);
    return UserIam::UserAuth::ResultCode::SUCCESS;
}

UserIam::UserAuth::ResultCode PinAuthExecutorHdi::ConvertExecutorRole(const PinHdi::ExecutorRole in, UserIam::UserAuth::ExecutorRole &out)
{
    static const std::map<PinHdi::ExecutorRole, UserIam::UserAuth::ExecutorRole> data = {
        { PinHdi::ExecutorRole::COLLECTOR, UserIam::UserAuth::ExecutorRole::COLLECTOR },
        { PinHdi::ExecutorRole::VERIFIER, UserIam::UserAuth::ExecutorRole::VERIFIER },
        { PinHdi::ExecutorRole::ALL_IN_ONE, UserIam::UserAuth::ExecutorRole::ALL_IN_ONE},
    };
    if (data.count(in) == 0) {
        IAM_LOGE("executorRole %{public}d is invalid", in);
        return UserIam::UserAuth::ResultCode::GENERAL_ERROR;
    }
    out = data.at(in);
    return UserIam::UserAuth::ResultCode::SUCCESS;
}

UserIam::UserAuth::ResultCode PinAuthExecutorHdi::ConvertExecutorSecureLevel(const PinHdi::ExecutorSecureLevel in,
    UserIam::UserAuth::ExecutorSecureLevel &out)
{
    static const std::map<PinHdi::ExecutorSecureLevel, UserIam::UserAuth::ExecutorSecureLevel> data = {
        { PinHdi::ExecutorSecureLevel::ESL0, UserIam::UserAuth::ExecutorSecureLevel::ESL0 },
        { PinHdi::ExecutorSecureLevel::ESL1, UserIam::UserAuth::ExecutorSecureLevel::ESL1 },
        { PinHdi::ExecutorSecureLevel::ESL2, UserIam::UserAuth::ExecutorSecureLevel::ESL2 },
        { PinHdi::ExecutorSecureLevel::ESL3, UserIam::UserAuth::ExecutorSecureLevel::ESL3 },
    };
    if (data.count(in) == 0) {
        IAM_LOGE("executorSecureLevel %{public}d is invalid", in);
        return UserIam::UserAuth::ResultCode::GENERAL_ERROR;
    }
    out = data.at(in);
    return UserIam::UserAuth::ResultCode::SUCCESS;
}

UserIam::UserAuth::ResultCode PinAuthExecutorHdi::ConvertResultCode(const int32_t in)
{
    HDF_STATUS hdfIn = static_cast<HDF_STATUS>(in);
    static const std::map<HDF_STATUS, UserIam::UserAuth::ResultCode> data = {
        {HDF_SUCCESS, UserIam::UserAuth::ResultCode::SUCCESS},
        {HDF_FAILURE, UserIam::UserAuth::ResultCode::FAIL},
        {HDF_ERR_TIMEOUT, UserIam::UserAuth::ResultCode::TIMEOUT},
        {HDF_ERR_QUEUE_FULL, UserIam::UserAuth::ResultCode::BUSY},
        {HDF_ERR_DEVICE_BUSY, UserIam::UserAuth::ResultCode::BUSY},
    };

    UserIam::UserAuth::ResultCode out;
    if (data.count(hdfIn) == 0) {
        out = UserIam::UserAuth::ResultCode::GENERAL_ERROR;
    } else {
        out = data.at(hdfIn);
    }
    IAM_LOGE("covert hdi result code %{public}d to framework result code %{public}d", in, out);
    return out;
}
} // PinAuth
} // UserIAM
} // OHOS