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

#include "pinauth_manager.h"
#include "iam_logger.h"

#define LOG_LABEL UserIAM::Common::LABEL_PIN_AUTH_SA

namespace OHOS {
namespace UserIAM {
namespace PinAuth {
PinAuthManager::PinAuthManager() = default;
PinAuthManager::~PinAuthManager() = default;
bool PinAuthManager::RegisterInputer(uint32_t tokenId, sptr<IRemoteInputer> &inputer)
{
    std::lock_guard<std::mutex> guard(mutex_);
    IAM_LOGI("start, tokenId = %{public}u", tokenId);
    if (pinAuthInputerMap_.find(tokenId) != pinAuthInputerMap_.end()) {
        IAM_LOGE("inputer is already register, do not repeat");
        return false;
    }
    pinAuthInputerMap_.emplace(tokenId, inputer);
    sptr<IRemoteObject::DeathRecipient> dr = new (std::nothrow) ResPinauthInputerDeathRecipient(tokenId);
    if (dr == nullptr || inputer->AsObject() == nullptr) {
        IAM_LOGE("dr or inputer's object is nullptr");
    } else {
        if (!inputer->AsObject()->AddDeathRecipient(dr)) {
            IAM_LOGE("add death recipient fail");
        }
    }
    IAM_LOGI("end");
    return true;
}

void PinAuthManager::UnRegisterInputer(uint32_t tokenId)
{
    std::lock_guard<std::mutex> guard(mutex_);
    IAM_LOGI("start, tokenId = %{public}u", tokenId);
    if (pinAuthInputerMap_.find(tokenId) != pinAuthInputerMap_.end()) {
        pinAuthInputerMap_.erase(tokenId);
        IAM_LOGE("pinAuthInputerMap_ erase success");
    }
    IAM_LOGI("end");
}

sptr<IRemoteInputer> PinAuthManager::getInputerLock(uint64_t uid)
{
    std::lock_guard<std::mutex> guard(mutex_);
    IAM_LOGI("start");
    auto pinAuthInputer = pinAuthInputerMap_.find(uid);
    if (pinAuthInputer != pinAuthInputerMap_.end()) {
        IAM_LOGI("find pinAuthInputer");
        return pinAuthInputer->second;
    } else {
        IAM_LOGI("pinAuthInputer is not found");
    }
    return nullptr;
}

PinAuthManager::ResPinauthInputerDeathRecipient::ResPinauthInputerDeathRecipient(uint64_t uid) : uid_(uid) { }

void PinAuthManager::ResPinauthInputerDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    IAM_LOGI("start");
    if (remote == nullptr) {
        IAM_LOGE("remote is nullptr");
        return;
    }
    PinAuthManager::GetInstance().UnRegisterInputer(uid_);
}
} // namespace PinAuth
} // namespace UserIAM
} // namespace OHOS
