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

#include "pin_auth_verifier_hdi.h"

#include "iam_logger.h"
#include "pin_auth_executor_callback_hdi.h"
#include "pin_auth_executor_hdi_common.h"

#define LOG_TAG "PIN_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
PinAuthVerifierHdi::PinAuthVerifierHdi(const sptr<IVerifier> &verifierProxy)
    : verifierProxy_(verifierProxy)
{
}

UserAuth::ResultCode PinAuthVerifierHdi::GetExecutorInfo(UserAuth::ExecutorInfo &info)
{
    IAM_LOGI("start");
    if (verifierProxy_ == nullptr) {
        IAM_LOGE("verifierProxy is null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }

    ExecutorInfo verifierInfo = {};
    UserAuth::ResultCode result = ConvertHdiResultCode(verifierProxy_->GetExecutorInfo(verifierInfo));
    if (result != UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("GetExecutorInfo of verifier fail:%{public}d", result);
        return result;
    }
    if (MoveHdiExecutorInfo(verifierInfo, info) != UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("MoveHdiExecutorInfo fail");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    return UserAuth::ResultCode::SUCCESS;
}

UserAuth::ResultCode PinAuthVerifierHdi::OnRegisterFinish(const std::vector<uint64_t> &templateIdList,
    const std::vector<uint8_t> &frameworkPublicKey, const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGI("start");
    if (verifierProxy_ == nullptr) {
        IAM_LOGE("verifierProxy is null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    int32_t status = verifierProxy_->OnRegisterFinish(templateIdList, frameworkPublicKey, extraInfo);
    UserAuth::ResultCode result = ConvertHdiResultCode(status);
    if (result != UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("OnRegisterFinish fail:%{public}d", result);
        return result;
    }
    return UserAuth::ResultCode::SUCCESS;
}

UserAuth::ResultCode PinAuthVerifierHdi::Cancel(uint64_t scheduleId)
{
    IAM_LOGI("start");
    if (verifierProxy_ == nullptr) {
        IAM_LOGE("verifierProxy is null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    int32_t status = verifierProxy_->Cancel(scheduleId);
    UserAuth::ResultCode result = ConvertHdiResultCode(status);
    if (result != UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("Cancel fail:%{public}d", result);
        return result;
    }
    return UserAuth::ResultCode::SUCCESS;
}

UserAuth::ResultCode PinAuthVerifierHdi::SendMessage(
    uint64_t scheduleId, int32_t srcRole, const std::vector<uint8_t> &msg)
{
    IAM_LOGI("start");
    if (verifierProxy_ == nullptr) {
        IAM_LOGE("verifierProxy is null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    int32_t status = verifierProxy_->SendMessage(scheduleId, srcRole, msg);
    UserAuth::ResultCode result = ConvertHdiResultCode(status);
    if (result != UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("SendMessage fail:%{public}d", result);
        return result;
    }
    return UserAuth::ResultCode::SUCCESS;
}

UserAuth::ResultCode PinAuthVerifierHdi::Authenticate(uint64_t scheduleId, const UserAuth::AuthenticateParam &param,
    const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj)
{
    IAM_LOGI("start");
    if (verifierProxy_ == nullptr) {
        IAM_LOGE("verifierProxy is null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    if (callbackObj == nullptr || param.templateIdList.empty()) {
        IAM_LOGE("get bad param is null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    UserAuth::ExecutorParam executorParam = {
        .tokenId = param.tokenId,
        .authIntent = param.authIntent,
        .scheduleId = scheduleId,
    };
    auto callback = sptr<IExecutorCallback>(
        new (std::nothrow) PinAuthExecutorCallbackHdi(callbackObj, executorParam, GET_DATA_MODE_NONE));
    if (callback == nullptr) {
        IAM_LOGE("get verifier callback null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    int32_t status = verifierProxy_->Authenticate(scheduleId, param.templateIdList, param.extraInfo, callback);
    UserAuth::ResultCode result = ConvertHdiResultCode(status);
    if (result != UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("Authenticate fail:%{public}d", result);
        return result;
    }
    return UserAuth::ResultCode::SUCCESS;
}

UserAuth::ResultCode PinAuthVerifierHdi::NotifyCollectorReady(uint64_t scheduleId)
{
    IAM_LOGI("start");
    if (verifierProxy_ == nullptr) {
        IAM_LOGE("verifierProxy is null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    int32_t status = verifierProxy_->NotifyCollectorReady(scheduleId);
    UserAuth::ResultCode result = ConvertHdiResultCode(status);
    if (result != UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("NotifyCollectorReady fail:%{public}d", result);
        return result;
    }
    return UserAuth::ResultCode::SUCCESS;
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS