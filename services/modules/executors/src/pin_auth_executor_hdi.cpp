/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "hisysevent.h"

#include "iam_check.h"
#include "iam_defines.h"
#include "iam_logger.h"
#include "pin_auth_executor_callback_hdi.h"

#define LOG_LABEL UserIam::Common::LABEL_PIN_AUTH_SA

namespace OHOS {
namespace UserIam {
namespace PinAuth {
using IamResultCode = OHOS::UserIam::UserAuth::ResultCode;
using IamExecutorRole = UserIam::UserAuth::ExecutorRole;

PinAuthExecutorHdi::PinAuthExecutorHdi(const sptr<HDI::PinAuth::V1_1::IExecutor> &executorProxy)
    : executorProxy_(executorProxy)
{
}

IamResultCode PinAuthExecutorHdi::GetExecutorInfo(UserAuth::ExecutorInfo &info)
{
    if (executorProxy_ == nullptr) {
        IAM_LOGE("executorProxy is null");
        return IamResultCode::GENERAL_ERROR;
    }

    ExecutorInfo localInfo = { };
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
        IAM_LOGE("OnRegisterFinish fail result %{public}d", result);
        return result;
    }

    HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::USERIAM_PIN, "USERIAM_TEMPLATE_CHANGE",
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
        IAM_LOGE("OnRegisterFinish fail ret=%{public}d", result);
        return result;
    }
    return IamResultCode::SUCCESS;
}

IamResultCode PinAuthExecutorHdi::Enroll(uint64_t scheduleId, const UserAuth::EnrollParam &param,
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
    auto callback = sptr<IExecutorCallback>(
        new (std::nothrow) PinAuthExecutorCallbackHdi(callbackObj, shared_from_this(), param.tokenId, true));
    if (callback == nullptr) {
        IAM_LOGE("callback is null");
        return IamResultCode::GENERAL_ERROR;
    }
    int32_t status = executorProxy_->EnrollV1_1(scheduleId, param.extraInfo, callback);
    IamResultCode result = ConvertResultCode(status);
    if (result != IamResultCode::SUCCESS) {
        IAM_LOGE("Enroll fail ret=%{public}d", result);
        return result;
    }
    return IamResultCode::SUCCESS;
}

IamResultCode PinAuthExecutorHdi::Authenticate(uint64_t scheduleId, const UserAuth::AuthenticateParam &param,
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
    auto callback = sptr<IExecutorCallback>(
        new (std::nothrow) PinAuthExecutorCallbackHdi(callbackObj, shared_from_this(), param.tokenId, false));
    if (callback == nullptr) {
        IAM_LOGE("callback is null");
        return IamResultCode::GENERAL_ERROR;
    }
    if (param.templateIdList.size() == 0) {
        IAM_LOGE("Error param");
        return IamResultCode::GENERAL_ERROR;
    }
    int32_t status = executorProxy_->AuthenticateV1_1(scheduleId, param.templateIdList[0], param.extraInfo, callback);
    IamResultCode result = ConvertResultCode(status);
    if (result != IamResultCode::SUCCESS) {
        IAM_LOGE("Authenticate fail ret=%{public}d", result);
        return result;
    }
    return IamResultCode::SUCCESS;
}

IamResultCode PinAuthExecutorHdi::Identify(uint64_t scheduleId, const UserAuth::IdentifyParam &param,
    const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj)
{
    IAM_LOGI("Adaptor frame interface, temporarily useless");
    static_cast<void>(scheduleId);
    static_cast<void>(param);
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

IamResultCode PinAuthExecutorHdi::SendCommand(UserAuth::PropertyMode commandId, const std::vector<uint8_t> &extraInfo,
    const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj)
{
    IAM_LOGI("Adaptor frame interface, temporarily useless");
    static_cast<void>(commandId);
    static_cast<void>(extraInfo);
    static_cast<void>(callbackObj);
    return IamResultCode::SUCCESS;
}

UserAuth::ResultCode PinAuthExecutorHdi::GetProperty(const std::vector<uint64_t> &templateIdList,
    const std::vector<UserAuth::Attributes::AttributeKey> &keys, UserAuth::Property &property)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(executorProxy_ != nullptr, IamResultCode::GENERAL_ERROR);

    std::vector<GetPropertyType> propertyTypes;
    IamResultCode result = ConvertAttributeKeyVectorToPropertyType(keys, propertyTypes);
    IF_FALSE_LOGE_AND_RETURN_VAL(result == IamResultCode::SUCCESS, IamResultCode::GENERAL_ERROR);

    Property hdiProperty;
    int32_t status = executorProxy_->GetProperty(templateIdList, propertyTypes, hdiProperty);
    result = ConvertResultCode(status);
    if (result != IamResultCode::SUCCESS) {
        IAM_LOGE("SendCommand fail result %{public}d", result);
        return result;
    }
    MoveHdiProperty(hdiProperty, property);
    return IamResultCode::SUCCESS;
}

UserAuth::ResultCode PinAuthExecutorHdi::SetCachedTemplates(const std::vector<uint64_t> &templateIdList)
{
    static_cast<void>(templateIdList);
    IAM_LOGI("SetCachedTemplates is not supported");
    return IamResultCode::SUCCESS;
}

IamResultCode PinAuthExecutorHdi::MoveHdiExecutorInfo(ExecutorInfo &in, UserAuth::ExecutorInfo &out)
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

IamResultCode PinAuthExecutorHdi::MoveHdiTemplateInfo(TemplateInfo &in, UserAuth::TemplateInfo &out)
{
    out.executorType = in.executorType;
    out.freezingTime = in.lockoutDuration;
    out.remainTimes = in.remainAttempts;
    in.extraInfo.swap(out.extraInfo);
    return IamResultCode::SUCCESS;
}

void PinAuthExecutorHdi::MoveHdiProperty(Property &in, UserAuth::Property &out)
{
    out.authSubType = in.authSubType;
    out.lockoutDuration = in.lockoutDuration;
    out.remainAttempts = in.remainAttempts;
}

IamResultCode PinAuthExecutorHdi::ConvertCommandId(const UserAuth::PropertyMode in, CommandId &out)
{
    IAM_LOGI("Adaptor frame interface, temporarily useless");
    static_cast<void>(in);
    static_cast<void>(out);
    return IamResultCode::SUCCESS;
}

IamResultCode PinAuthExecutorHdi::ConvertAuthType(const AuthType in, UserAuth::AuthType &out)
{
    static const std::map<AuthType, UserAuth::AuthType> data = {
        {AuthType::PIN, UserAuth::AuthType::PIN},
    };
    if (data.count(in) == 0) {
        IAM_LOGE("authType %{public}d is invalid", in);
        return IamResultCode::GENERAL_ERROR;
    }
    out = data.at(in);
    return IamResultCode::SUCCESS;
}

IamResultCode PinAuthExecutorHdi::ConvertExecutorRole(const ExecutorRole in, IamExecutorRole &out)
{
    static const std::map<ExecutorRole, IamExecutorRole> data = {
        { ExecutorRole::COLLECTOR, IamExecutorRole::COLLECTOR },
        { ExecutorRole::VERIFIER, IamExecutorRole::VERIFIER },
        { ExecutorRole::ALL_IN_ONE, IamExecutorRole::ALL_IN_ONE},
    };
    if (data.count(in) == 0) {
        IAM_LOGE("executorRole %{public}d is invalid", in);
        return IamResultCode::GENERAL_ERROR;
    }
    out = data.at(in);
    return IamResultCode::SUCCESS;
}

IamResultCode PinAuthExecutorHdi::ConvertExecutorSecureLevel(const ExecutorSecureLevel in,
    UserAuth::ExecutorSecureLevel &out)
{
    static const std::map<ExecutorSecureLevel, UserAuth::ExecutorSecureLevel> data = {
        { ExecutorSecureLevel::ESL0, UserAuth::ExecutorSecureLevel::ESL0 },
        { ExecutorSecureLevel::ESL1, UserAuth::ExecutorSecureLevel::ESL1 },
        { ExecutorSecureLevel::ESL2, UserAuth::ExecutorSecureLevel::ESL2 },
        { ExecutorSecureLevel::ESL3, UserAuth::ExecutorSecureLevel::ESL3 },
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
        {HDF_ERR_INVALID_PARAM, IamResultCode::INVALID_PARAMETERS},
    };

    IamResultCode out;
    if (data.count(hdfIn) == 0) {
        out = IamResultCode::GENERAL_ERROR;
    } else {
        out = data.at(hdfIn);
    }
    IAM_LOGI("covert hdi result code %{public}d to framework result code %{public}d", in, out);
    return out;
}

IamResultCode PinAuthExecutorHdi::ConvertAttributeKeyVectorToPropertyType(
    const std::vector<UserAuth::Attributes::AttributeKey> inItems, std::vector<GetPropertyType> &outItems)
{
    outItems.clear();
    for (auto &inItem : inItems) {
        if (inItem == UserAuth::Attributes::ATTR_ENROLL_PROGRESS ||
            inItem == UserAuth::Attributes::ATTR_SENSOR_INFO) {
            continue;
        }
        GetPropertyType outItem;
        IamResultCode result = ConvertAttributeKeyToPropertyType(inItem, outItem);
        IF_FALSE_LOGE_AND_RETURN_VAL(result == IamResultCode::SUCCESS, IamResultCode::GENERAL_ERROR);
        outItems.push_back(outItem);
    }

    return IamResultCode::SUCCESS;
}

IamResultCode PinAuthExecutorHdi::ConvertAttributeKeyToPropertyType(const UserAuth::Attributes::AttributeKey in,
    GetPropertyType &out)
{
    static const std::map<UserAuth::Attributes::AttributeKey, GetPropertyType> data = {
        { UserAuth::Attributes::ATTR_PIN_SUB_TYPE, GetPropertyType::AUTH_SUB_TYPE },
        { UserAuth::Attributes::ATTR_FREEZING_TIME, GetPropertyType::LOCKOUT_DURATION },
        { UserAuth::Attributes::ATTR_REMAIN_TIMES, GetPropertyType::REMAIN_ATTEMPTS },
    };

    auto iter = data.find(in);
    if (iter == data.end()) {
        IAM_LOGE("attribute %{public}d is invalid", in);
        return IamResultCode::GENERAL_ERROR;
    } else {
        out = iter->second;
    }
    IAM_LOGI("covert hdi result code %{public}d to framework result code %{public}d", in, out);
    return IamResultCode::SUCCESS;
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
