/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "pin_auth_all_in_one_hdi.h"

#include <map>

#include "hdf_base.h"

#include "iam_check.h"
#include "iam_defines.h"
#include "iam_logger.h"
#include "pin_auth_executor_callback_hdi.h"
#include "pin_auth_executor_hdi_common.h"

#define LOG_TAG "PIN_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
PinAuthAllInOneHdi::PinAuthAllInOneHdi(const sptr<IAllInOneExecutor> &allInOneProxy)
    : allInOneProxy_(allInOneProxy)
{
}

UserAuth::ResultCode PinAuthAllInOneHdi::GetExecutorInfo(UserAuth::ExecutorInfo &info)
{
    if (allInOneProxy_ == nullptr) {
        IAM_LOGE("allInOneProxy is null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }

    ExecutorInfo localInfo = { };
    int32_t status = allInOneProxy_->GetExecutorInfo(localInfo);
    UserAuth::ResultCode result = ConvertHdiResultCode(status);
    if (result != UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("GetExecutorInfo fail ret=%{public}d", result);
        return result;
    }
    int32_t ret = MoveHdiExecutorInfo(localInfo, info);
    if (ret != UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("MoveHdiExecutorInfo fail ret=%{public}d", ret);
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    return UserAuth::ResultCode::SUCCESS;
}

UserAuth::ResultCode PinAuthAllInOneHdi::OnRegisterFinish(const std::vector<uint64_t> &templateIdList,
    const std::vector<uint8_t> &frameworkPublicKey, const std::vector<uint8_t> &extraInfo)
{
    if (allInOneProxy_ == nullptr) {
        IAM_LOGE("allInOneProxy is null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    int32_t status = allInOneProxy_->OnRegisterFinish(templateIdList, frameworkPublicKey, extraInfo);
    UserAuth::ResultCode result = ConvertHdiResultCode(status);
    if (result != UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("OnRegisterFinish fail result %{public}d", result);
        return result;
    }

    return UserAuth::ResultCode::SUCCESS;
}

UserAuth::ResultCode PinAuthAllInOneHdi::SendMessage(
    uint64_t scheduleId, int32_t srcRole, const std::vector<uint8_t> &msg)
{
    if (allInOneProxy_ == nullptr) {
        IAM_LOGE("allInOneProxy is null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    int32_t status = allInOneProxy_->SendMessage(scheduleId, srcRole, msg);
    UserAuth::ResultCode result = ConvertHdiResultCode(status);
    if (result != UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("SendMessage fail result %{public}d", result);
        return result;
    }
    return UserAuth::ResultCode::SUCCESS;
}

UserAuth::ResultCode PinAuthAllInOneHdi::OnSetData(uint64_t scheduleId, uint64_t authSubType,
    const std::vector<uint8_t> &data, int32_t errorCode)
{
    if (allInOneProxy_ == nullptr) {
        IAM_LOGE("allInOneProxy is null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    int32_t status = allInOneProxy_->SetData(scheduleId, authSubType, data, errorCode);
    UserAuth::ResultCode result = ConvertHdiResultCode(status);
    if (result != UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("OnSetData fail ret=%{public}d", result);
        return result;
    }
    return UserAuth::ResultCode::SUCCESS;
}

UserAuth::ResultCode PinAuthAllInOneHdi::Enroll(uint64_t scheduleId, const UserAuth::EnrollParam &param,
    const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj)
{
    if (allInOneProxy_ == nullptr) {
        IAM_LOGE("allInOneProxy is null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    if (callbackObj == nullptr) {
        IAM_LOGE("callbackObj is null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    UserAuth::ExecutorParam executorParam = {
        .tokenId = param.tokenId,
        .scheduleId = scheduleId,
    };
    auto callback = sptr<IExecutorCallback>(new (std::nothrow) PinAuthExecutorCallbackHdi(callbackObj,
        shared_from_this(), executorParam, GET_DATA_MODE_ALL_IN_ONE_ENROLL));
    if (callback == nullptr) {
        IAM_LOGE("callback is null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    int32_t status = allInOneProxy_->Enroll(scheduleId, param.extraInfo, callback);
    UserAuth::ResultCode result = ConvertHdiResultCode(status);
    if (result != UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("Enroll fail ret=%{public}d", result);
        return result;
    }
    return UserAuth::ResultCode::SUCCESS;
}

UserAuth::ResultCode PinAuthAllInOneHdi::Authenticate(
    uint64_t scheduleId, const UserAuth::AuthenticateParam &param,
    const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj)
{
    if (allInOneProxy_ == nullptr) {
        IAM_LOGE("allInOneProxy is null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    if (callbackObj == nullptr) {
        IAM_LOGE("callbackObj is null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    UserAuth::ExecutorParam executorParam = {
        .tokenId = param.tokenId,
        .authIntent = param.authIntent,
        .scheduleId = scheduleId,
    };
    auto callback = sptr<IExecutorCallback>(new (std::nothrow) PinAuthExecutorCallbackHdi(callbackObj,
        shared_from_this(), executorParam, GET_DATA_MODE_ALL_IN_ONE_AUTH));
    if (callback == nullptr) {
        IAM_LOGE("callback is null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    if (param.templateIdList.size() == 0) {
        IAM_LOGE("Error param");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    int32_t status = allInOneProxy_->Authenticate(scheduleId, param.templateIdList,
        param.extraInfo, callback);
    UserAuth::ResultCode result = ConvertHdiResultCode(status);
    if (result != UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("Authenticate fail ret=%{public}d", result);
        return result;
    }
    return UserAuth::ResultCode::SUCCESS;
}

UserAuth::ResultCode PinAuthAllInOneHdi::Delete(const std::vector<uint64_t> &templateIdList)
{
    if (allInOneProxy_ == nullptr) {
        IAM_LOGE("allInOneProxy is null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    if (templateIdList.empty()) {
        IAM_LOGE("templateIdList is empty");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    int32_t status = allInOneProxy_->Delete(templateIdList[0]);
    UserAuth::ResultCode result = ConvertHdiResultCode(status);
    if (result != UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("Delete fail ret=%{public}d", result);
        return result;
    }
    return UserAuth::ResultCode::SUCCESS;
}

UserAuth::ResultCode PinAuthAllInOneHdi::Cancel(uint64_t scheduleId)
{
    if (allInOneProxy_ == nullptr) {
        IAM_LOGE("allInOneProxy is null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    int32_t status = allInOneProxy_->Cancel(scheduleId);
    UserAuth::ResultCode result = ConvertHdiResultCode(status);
    if (result != UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("Cancel fail ret=%{public}d", result);
        return result;
    }
    return UserAuth::ResultCode::SUCCESS;
}

UserAuth::ResultCode PinAuthAllInOneHdi::GetProperty(const std::vector<uint64_t> &templateIdList,
    const std::vector<UserAuth::Attributes::AttributeKey> &keys, UserAuth::Property &property)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(allInOneProxy_ != nullptr, UserAuth::ResultCode::GENERAL_ERROR);

    std::vector<int32_t> propertyTypes;
    UserAuth::ResultCode result = ConvertAttributeKeyVectorToPropertyType(keys, propertyTypes);
    IF_FALSE_LOGE_AND_RETURN_VAL(result == UserAuth::ResultCode::SUCCESS, UserAuth::ResultCode::GENERAL_ERROR);

    Property hdiProperty;
    int32_t status = allInOneProxy_->GetProperty(templateIdList, propertyTypes, hdiProperty);
    result = ConvertHdiResultCode(status);
    if (result != UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("SendCommand fail result %{public}d", result);
        return result;
    }
    MoveHdiProperty(hdiProperty, property);
    return UserAuth::ResultCode::SUCCESS;
}

void PinAuthAllInOneHdi::MoveHdiProperty(Property &in, UserAuth::Property &out)
{
    out.authSubType = in.authSubType;
    out.lockoutDuration = in.lockoutDuration;
    out.remainAttempts = in.remainAttempts;
    out.nextFailLockoutDuration = in.nextFailLockoutDuration;
}

UserAuth::ResultCode PinAuthAllInOneHdi::ConvertAttributeKeyVectorToPropertyType(
    const std::vector<UserAuth::Attributes::AttributeKey> inItems, std::vector<int32_t> &outItems)
{
    outItems.clear();
    for (auto &inItem : inItems) {
        if (inItem == UserAuth::Attributes::ATTR_ENROLL_PROGRESS ||
            inItem == UserAuth::Attributes::ATTR_SENSOR_INFO) {
            continue;
        }
        int32_t outItem;
        UserAuth::ResultCode result = ConvertAttributeKeyToPropertyType(inItem, outItem);
        IF_FALSE_LOGE_AND_RETURN_VAL(result == UserAuth::ResultCode::SUCCESS, UserAuth::ResultCode::GENERAL_ERROR);
        outItems.push_back(outItem);
    }

    return UserAuth::ResultCode::SUCCESS;
}

UserAuth::ResultCode PinAuthAllInOneHdi::ConvertAttributeKeyToPropertyType(const UserAuth::Attributes::AttributeKey in,
    int32_t &out)
{
    static const std::map<UserAuth::Attributes::AttributeKey, GetPropertyType> data = {
        { UserAuth::Attributes::ATTR_PIN_SUB_TYPE, GetPropertyType::AUTH_SUB_TYPE },
        { UserAuth::Attributes::ATTR_FREEZING_TIME, GetPropertyType::LOCKOUT_DURATION },
        { UserAuth::Attributes::ATTR_REMAIN_TIMES, GetPropertyType::REMAIN_ATTEMPTS },
        { UserAuth::Attributes::ATTR_NEXT_FAIL_LOCKOUT_DURATION, GetPropertyType::NEXT_FAIL_LOCKOUT_DURATION },
    };

    auto iter = data.find(in);
    if (iter == data.end()) {
        IAM_LOGE("attribute %{public}d is invalid", in);
        return UserAuth::ResultCode::GENERAL_ERROR;
    } else {
        out = static_cast<int32_t>(iter->second);
    }
    IAM_LOGI("covert hdi result code %{public}d to framework result code %{public}d", in, out);
    return UserAuth::ResultCode::SUCCESS;
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
