/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "pin_auth_collector_hdi.h"

#include "iam_logger.h"
#include "pin_auth_executor_callback_hdi.h"
#include "pin_auth_executor_hdi_common.h"

#define LOG_TAG "PIN_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
PinAuthCollectorHdi::PinAuthCollectorHdi(const sptr<ICollector> &collectorProxy)
    : collectorProxy_(collectorProxy)
{
}

UserAuth::ResultCode PinAuthCollectorHdi::GetExecutorInfo(UserAuth::ExecutorInfo &info)
{
    IAM_LOGI("start");
    if (collectorProxy_ == nullptr) {
        IAM_LOGE("collectorProxy is null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }

    ExecutorInfo collectorInfo = {};
    UserAuth::ResultCode result = ConvertHdiResultCode(collectorProxy_->GetExecutorInfo(collectorInfo));
    if (result != UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("GetExecutorInfo of collector fail:%{public}d", result);
        return result;
    }
    if (MoveHdiExecutorInfo(collectorInfo, info) != UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("MoveHdiExecutorInfo fail");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    return UserAuth::ResultCode::SUCCESS;
}

UserAuth::ResultCode PinAuthCollectorHdi::OnRegisterFinish(const std::vector<uint64_t> &templateIdList,
    const std::vector<uint8_t> &frameworkPublicKey, const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGI("start");
    if (collectorProxy_ == nullptr) {
        IAM_LOGE("collectorProxy is null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    int32_t status = collectorProxy_->OnRegisterFinish(templateIdList, frameworkPublicKey, extraInfo);
    UserAuth::ResultCode result = ConvertHdiResultCode(status);
    if (result != UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("OnRegisterFinish fail:%{public}d", result);
        return result;
    }
    return UserAuth::ResultCode::SUCCESS;
}

UserAuth::ResultCode PinAuthCollectorHdi::Cancel(uint64_t scheduleId)
{
    IAM_LOGI("start");
    if (collectorProxy_ == nullptr) {
        IAM_LOGE("collectorProxy is null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    int32_t status = collectorProxy_->Cancel(scheduleId);
    UserAuth::ResultCode result = ConvertHdiResultCode(status);
    if (result != UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("Cancel fail:%{public}d", result);
        return result;
    }
    return UserAuth::ResultCode::SUCCESS;
}

UserAuth::ResultCode PinAuthCollectorHdi::SendMessage(
    uint64_t scheduleId, int32_t srcRole, const std::vector<uint8_t> &msg)
{
    IAM_LOGI("start");
    if (collectorProxy_ == nullptr) {
        IAM_LOGE("collectorProxy is null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    int32_t status = collectorProxy_->SendMessage(scheduleId, srcRole, msg);
    UserAuth::ResultCode result = ConvertHdiResultCode(status);
    if (result != UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("SendMessage fail:%{public}d", result);
        return result;
    }
    return UserAuth::ResultCode::SUCCESS;
}

UserAuth::ResultCode PinAuthCollectorHdi::Collect(uint64_t scheduleId, const UserAuth::CollectParam &param,
    const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj)
{
    IAM_LOGI("start");
    if (collectorProxy_ == nullptr) {
        IAM_LOGE("collectorProxy is null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    if (callbackObj == nullptr) {
        IAM_LOGE("callbackObj is null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    UserAuth::ExecutorParam executorParam = {
        .tokenId = param.collectorTokenId,
        .scheduleId = scheduleId,
    };
    auto callback = sptr<IExecutorCallback>(new (std::nothrow) PinAuthExecutorCallbackHdi(
        callbackObj, shared_from_this(), executorParam, GET_DATA_MODE_COLLECTOR_PIN_AUTH));
    if (callback == nullptr) {
        IAM_LOGE("get collector callback null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    int32_t status = collectorProxy_->Collect(scheduleId, param.extraInfo, callback);
    UserAuth::ResultCode result = ConvertHdiResultCode(status);
    if (result != UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("Authenticate fail:%{public}d", result);
        return result;
    }
    return UserAuth::ResultCode::SUCCESS;
}

UserAuth::ResultCode PinAuthCollectorHdi::OnSetData(uint64_t scheduleId, uint64_t authSubType,
    const std::vector<uint8_t> &data, int32_t errorCode)
{
    if (collectorProxy_ == nullptr) {
        IAM_LOGE("collectorProxy is null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    int32_t status = collectorProxy_->SetData(scheduleId, authSubType, data, errorCode);
    UserAuth::ResultCode result = ConvertHdiResultCode(status);
    if (result != UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("OnSetData fail ret:%{public}d", result);
        return result;
    }
    return UserAuth::ResultCode::SUCCESS;
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS