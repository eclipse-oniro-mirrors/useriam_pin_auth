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

#include "pin_auth_executor_hdi.h"

#include "hdf_base.h"
#include "iam_logger.h"
#include "iam_defines.h"
#include "hisysevent.h"
#include "pin_auth_executor_callback_hdi.h"

#define LOG_LABEL UserIam::Common::LABEL_PIN_AUTH_SA

namespace OHOS {
namespace UserIam {
namespace PinAuth {
using IamResultCode = OHOS::UserIam::UserAuth::ResultCode;
using IamExecutorRole = UserIam::UserAuth::ExecutorRole;

PinAuthExecutorHdi::PinAuthExecutorHdi(const sptr<HDI::PinAuth::V1_0::IExecutor> &executorProxy)
    : executorProxy_(executorProxy)
{
}

IamResultCode PinAuthExecutorHdi::GetExecutorInfo(UserAuth::ExecutorInfo &info)
{
    if (executorProxy_ == nullptr) {
        IAM_LOGE("executorProxy is null");
        return IamResultCode::GENERAL_ERROR;
    }

    PinHdi::ExecutorInfo localInfo = { };
    int32_t status = executorProxy_->GetExecutorInfo(localInfo);
    IamResultCode result = ConvertResultCode(status);
    if (result != IamResultCode::SUCCESS) {
        IAM_LOGE("GetExecutorInfo fail ret=%{public}d", result);
        return result;
    }
    int32_t ret = MoveHdiExecutorInfo(localInfo, info);
    if (ret != IamResultCode::SUCCESS) {
        IAM_LOGE("MoveHdiExecutorInfo fail ret=%{public}d", ret);
        return IamResultCode::GENERAL_ERROR;
    }
    return IamResultCode::SUCCESS;
}

IamResultCode PinAuthExecutorHdi::GetTemplateInfo(uint64_t templateId, UserAuth::TemplateInfo &info)
{
    if (executorProxy_ == nullptr) {
        IAM_LOGE("executorProxy is null");
        return IamResultCode::GENERAL_ERROR;
    }

    PinHdi::TemplateInfo localInfo = {};
    int32_t status = executorProxy_->GetTemplateInfo(templateId, localInfo);
    IamResultCode result = ConvertResultCode(status);
    if (result != IamResultCode::SUCCESS) {
        IAM_LOGE("GetTemplateInfo fail ret=%{public}d", result);
        return result;
    }
    int32_t ret = MoveHdiTemplateInfo(localInfo, info);
    if (ret != IamResultCode::SUCCESS) {
        IAM_LOGE("MoveHdiTemplateInfo fail ret=%{public}d", ret);
        return IamResultCode::GENERAL_ERROR;
    }
    return IamResultCode::SUCCESS;
}

IamResultCode PinAuthExecutorHdi::OnRegisterFinish(const std::vector<uint64_t> &templateIdList,
    const std::vector<uint8_t> &frameworkPublicKey, const std::vector<uint8_t> &extraInfo)
{
    if (executorProxy_ == nullptr) {
        IAM_LOGE("executorProxy is null");
        return IamResultCode::GENERAL_ERROR;
    }
    int32_t status = executorProxy_->OnRegisterFinish(templateIdList, frameworkPublicKey, extraInfo);
    IamResultCode result = ConvertResultCode(status);
    if (result != IamResultCode::SUCCESS) {
        IAM_LOGE("OnRegisterFinish fail result %{public}d", status);
        return result;
    }

    OHOS::HiviewDFX::HiSysEvent::Write("USERIAM_PIN", "USERIAM_TEMPLATE_CHANGE",
        OHOS::HiviewDFX::HiSysEvent::EventType::SECURITY, "EXECUTOR_TYPE", UserAuth::PIN,
        "CHANGE_TYPE", UserAuth::TRACE_DELETE_CREDENTIAL, "TRIGGER_REASON", "Reconciliation");
    return IamResultCode::SUCCESS;
}

IamResultCode PinAuthExecutorHdi::OnSetData(uint64_t scheduleId, uint64_t authSubType,
    const std::vector<uint8_t> &data)
{
    if (executorProxy_ == nullptr) {
        IAM_LOGE("executorProxy is null");
        return IamResultCode::GENERAL_ERROR;
    }
    int32_t status = executorProxy_->OnSetData(scheduleId, authSubType, data);
    IamResultCode result = ConvertResultCode(status);
    if (result != IamResultCode::SUCCESS) {
        IAM_LOGE("OnRegisterFinish fail ret=%{public}d", status);
        return result;
    }
    return IamResultCode::SUCCESS;
}

IamResultCode PinAuthExecutorHdi::Enroll(uint64_t scheduleId, uint32_t tokenId,
    const std::vector<uint8_t> &extraInfo, const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj)
{
    if (executorProxy_ == nullptr) {
        IAM_LOGE("executorProxy is null");
        return IamResultCode::GENERAL_ERROR;
    }
    if (callbackObj == nullptr) {
        IAM_LOGE("callbackObj is null");
        return IamResultCode::GENERAL_ERROR;
    }
    auto callback = sptr<PinHdi::IExecutorCallback>(new (std::nothrow) PinAuthExecutorCallbackHdi(callbackObj,
        shared_from_this(), tokenId));
    if (callback == nullptr) {
        IAM_LOGE("callback is null");
        return IamResultCode::GENERAL_ERROR;
    }
    int32_t status = executorProxy_->Enroll(scheduleId, extraInfo, callback);
    IamResultCode result = ConvertResultCode(status);
    if (result != IamResultCode::SUCCESS) {
        IAM_LOGE("Enroll fail ret=%{public}d", result);
        return result;
    }
    return IamResultCode::SUCCESS;
}

IamResultCode PinAuthExecutorHdi::Authenticate(uint64_t scheduleId, uint32_t tokenId,
    const std::vector<uint64_t> &templateIdList, const std::vector<uint8_t> &extraInfo,
    const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj)
{
    if (executorProxy_ == nullptr) {
        IAM_LOGE("executorProxy is null");
        return IamResultCode::GENERAL_ERROR;
    }
    if (callbackObj == nullptr) {
        IAM_LOGE("callbackObj is null");
        return IamResultCode::GENERAL_ERROR;
    }
    auto callback = sptr<PinHdi::IExecutorCallback>(new (std::nothrow) PinAuthExecutorCallbackHdi(callbackObj,
        shared_from_this(), tokenId));
    if (callback == nullptr) {
        IAM_LOGE("callback is null");
        return IamResultCode::GENERAL_ERROR;
    }
    if (templateIdList.size() == 0) {
        IAM_LOGE("Error param");
        return IamResultCode::GENERAL_ERROR;
    }
    int32_t status = executorProxy_->Authenticate(scheduleId, templateIdList[0], extraInfo, callback);
    IamResultCode result = ConvertResultCode(status);
    if (result != IamResultCode::SUCCESS) {
        IAM_LOGE("Authenticate fail ret=%{public}d", result);
        return result;
    }
    return IamResultCode::SUCCESS;
}

IamResultCode PinAuthExecutorHdi::Identify(uint64_t scheduleId, uint32_t tokenId,
    const std::vector<uint8_t> &extraInfo, const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj)
{
    IAM_LOGI("Adaptor frame interface, temporarily useless");
    static_cast<void>(scheduleId);
    static_cast<void>(tokenId);
    static_cast<void>(extraInfo);
    static_cast<void>(callbackObj);
    return IamResultCode::SUCCESS;
}

IamResultCode PinAuthExecutorHdi::Delete(const std::vector<uint64_t> &templateIdList)
{
    if (executorProxy_ == nullptr) {
        IAM_LOGE("executorProxy is null");
        return IamResultCode::GENERAL_ERROR;
    }
    int32_t status = executorProxy_->Delete(templateIdList[0]);
    IamResultCode result = ConvertResultCode(status);
    if (result != IamResultCode::SUCCESS) {
        IAM_LOGE("Delete fail ret=%{public}d", result);
        return result;
    }
    return IamResultCode::SUCCESS;
}

IamResultCode PinAuthExecutorHdi::Cancel(uint64_t scheduleId)
{
    if (executorProxy_ == nullptr) {
        IAM_LOGE("executorProxy is null");
        return IamResultCode::GENERAL_ERROR;
    }
    int32_t status = executorProxy_->Cancel(scheduleId);
    IamResultCode result = ConvertResultCode(status);
    if (result != IamResultCode::SUCCESS) {
        IAM_LOGE("Cancel fail ret=%{public}d", result);
        return result;
    }
    return IamResultCode::SUCCESS;
}

IamResultCode PinAuthExecutorHdi::SendCommand(UserAuth::PropertyMode commandId,
    const std::vector<uint8_t> &extraInfo, const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj)
{
    IAM_LOGI("Adaptor frame interface, temporarily useless");
    static_cast<void>(commandId);
    static_cast<void>(extraInfo);
    static_cast<void>(callbackObj);
    return IamResultCode::SUCCESS;
}

IamResultCode PinAuthExecutorHdi::MoveHdiExecutorInfo(PinHdi::ExecutorInfo &in, UserAuth::ExecutorInfo &out)
{
    out.executorSensorHint = static_cast<uint32_t>(in.sensorId);
    out.executorMatcher = in.executorType;
    int32_t ret = ConvertExecutorRole(in.executorRole, out.executorRole);
    if (ret != IamResultCode::SUCCESS) {
        IAM_LOGE("executorProxy is null");
        return IamResultCode::GENERAL_ERROR;
    }
    ret = ConvertAuthType(in.authType, out.authType);
    if (ret != IamResultCode::SUCCESS) {
        IAM_LOGE("ConvertAuthType fail ret=%{public}d", ret);
        return IamResultCode::GENERAL_ERROR;
    }
    ret = ConvertExecutorSecureLevel(in.esl, out.esl);
    if (ret != IamResultCode::SUCCESS) {
        IAM_LOGE("ConvertExecutorSecureLevel fail ret=%{public}d", ret);
        return IamResultCode::GENERAL_ERROR;
    }
    in.publicKey.swap(out.publicKey);
    return IamResultCode::SUCCESS;
}

IamResultCode PinAuthExecutorHdi::MoveHdiTemplateInfo(PinHdi::TemplateInfo &in, UserAuth::TemplateInfo &out)
{
    out.executorType = in.executorType;
    out.freezingTime = in.lockoutDuration;
    out.remainTimes = in.remainAttempts;
    in.extraInfo.swap(out.extraInfo);
    return IamResultCode::SUCCESS;
}

IamResultCode PinAuthExecutorHdi::ConvertCommandId(const UserAuth::PropertyMode in, PinHdi::CommandId &out)
{
    IAM_LOGI("Adaptor frame interface, temporarily useless");
    static_cast<void>(in);
    static_cast<void>(out);
    return IamResultCode::SUCCESS;
}

IamResultCode PinAuthExecutorHdi::ConvertAuthType(const PinHdi::AuthType in, UserAuth::AuthType &out)
{
    static const std::map<PinHdi::AuthType, UserAuth::AuthType> data = {
        {PinHdi::PIN, UserAuth::AuthType::PIN},
    };
    if (data.count(in) == 0) {
        IAM_LOGE("authType %{public}d is invalid", in);
        return IamResultCode::GENERAL_ERROR;
    }
    out = data.at(in);
    return IamResultCode::SUCCESS;
}

IamResultCode PinAuthExecutorHdi::ConvertExecutorRole(const PinHdi::ExecutorRole in, IamExecutorRole &out)
{
    static const std::map<PinHdi::ExecutorRole, IamExecutorRole> data = {
        { PinHdi::ExecutorRole::COLLECTOR, IamExecutorRole::COLLECTOR },
        { PinHdi::ExecutorRole::VERIFIER, IamExecutorRole::VERIFIER },
        { PinHdi::ExecutorRole::ALL_IN_ONE, IamExecutorRole::ALL_IN_ONE},
    };
    if (data.count(in) == 0) {
        IAM_LOGE("executorRole %{public}d is invalid", in);
        return IamResultCode::GENERAL_ERROR;
    }
    out = data.at(in);
    return IamResultCode::SUCCESS;
}

IamResultCode PinAuthExecutorHdi::ConvertExecutorSecureLevel(const PinHdi::ExecutorSecureLevel in,
    UserAuth::ExecutorSecureLevel &out)
{
    static const std::map<PinHdi::ExecutorSecureLevel, UserAuth::ExecutorSecureLevel> data = {
        { PinHdi::ExecutorSecureLevel::ESL0, UserAuth::ExecutorSecureLevel::ESL0 },
        { PinHdi::ExecutorSecureLevel::ESL1, UserAuth::ExecutorSecureLevel::ESL1 },
        { PinHdi::ExecutorSecureLevel::ESL2, UserAuth::ExecutorSecureLevel::ESL2 },
        { PinHdi::ExecutorSecureLevel::ESL3, UserAuth::ExecutorSecureLevel::ESL3 },
    };
    if (data.count(in) == 0) {
        IAM_LOGE("executorSecureLevel %{public}d is invalid", in);
        return IamResultCode::GENERAL_ERROR;
    }
    out = data.at(in);
    return IamResultCode::SUCCESS;
}

IamResultCode PinAuthExecutorHdi::ConvertResultCode(const int32_t in)
{
    HDF_STATUS hdfIn = static_cast<HDF_STATUS>(in);
    static const std::map<HDF_STATUS, IamResultCode> data = {
        {HDF_SUCCESS, IamResultCode::SUCCESS},
        {HDF_FAILURE, IamResultCode::FAIL},
        {HDF_ERR_TIMEOUT, IamResultCode::TIMEOUT},
        {HDF_ERR_QUEUE_FULL, IamResultCode::BUSY},
        {HDF_ERR_DEVICE_BUSY, IamResultCode::BUSY},
    };

    IamResultCode out;
    if (data.count(hdfIn) == 0) {
        out = IamResultCode::GENERAL_ERROR;
    } else {
        out = data.at(hdfIn);
    }
    IAM_LOGE("covert hdi result code %{public}d to framework result code %{public}d", in, out);
    return out;
}
} // PinAuth
} // UserIam
} // OHOS
