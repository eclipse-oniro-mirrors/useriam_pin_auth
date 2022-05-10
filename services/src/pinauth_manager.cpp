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
#include <cinttypes>
#include "pinauth_log_wrapper.h"

namespace OHOS {
namespace UserIAM {
namespace PinAuth {
PinAuthManager::PinAuthManager() = default;
PinAuthManager::~PinAuthManager() = default;
bool PinAuthManager::RegisterInputer(uint64_t uid, sptr<IRemoteInputer> &inputer)
{
    std::lock_guard<std::mutex> guard(mutex_);
    PINAUTH_HILOGI(MODULE_SERVICE,
        "PinAuthManager::RegisterInputer start uid 0xXXXX%{public}04" PRIx64 " is called", MASK & uid);
    if (pinAuthInputerMap_.find(uid) != pinAuthInputerMap_.end()) {
        PINAUTH_HILOGE(MODULE_SERVICE,
            "PinAuthManager::RegisterInputer pinAuthController is already register, do not repeat");
        return false;
    }
    pinAuthInputerMap_.emplace(uid, inputer);
    sptr<IRemoteObject::DeathRecipient> dr = new (std::nothrow) ResPinauthInputerDeathRecipient(uid);
    if (dr == nullptr || inputer->AsObject() == nullptr) {
        PINAUTH_HILOGE(MODULE_SERVICE, "dr or inputer->AsObject() is nullptr");
    } else {
        if (!inputer->AsObject()->AddDeathRecipient(dr)) {
            PINAUTH_HILOGE(MODULE_SERVICE, "Failed to add death recipient ResIExecutorCallbackDeathRecipient");
        }
    }
    PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthManager::RegisterInputer register end");
    return true;
}

void PinAuthManager::UnRegisterInputer(uint64_t uid)
{
    std::lock_guard<std::mutex> guard(mutex_);
    PINAUTH_HILOGI(MODULE_SERVICE,
        "PinAuthManager::UnRegisterInputer start uid 0xXXXX%{public}04" PRIx64 " is called", MASK & uid);
    if (pinAuthInputerMap_.find(uid) != pinAuthInputerMap_.end()) {
        pinAuthInputerMap_.erase(uid);
        PINAUTH_HILOGE(MODULE_SERVICE, "pinAuthInputerMap_ erase success");
    }
    PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthManager::UnRegisterInputer() is called end");
}

sptr<IRemoteInputer> PinAuthManager::getInputerLock(uint64_t uid)
{
    std::lock_guard<std::mutex> guard(mutex_);
    PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthManager::getInputerLock start");
    auto pinAuthInputer = pinAuthInputerMap_.find(uid);
    if (pinAuthInputer != pinAuthInputerMap_.end()) {
        PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthManager::getInputer has pinAuthInputer");
        return pinAuthInputer->second;
    } else {
        PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthManager::getInputer pinAuthInputer is not found");
    }
    return nullptr;
}

PinAuthManager::ResPinauthInputerDeathRecipient::ResPinauthInputerDeathRecipient(uint64_t uid) : uid_(uid) { }

void PinAuthManager::ResPinauthInputerDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthManager::OnRemoteDied start");
    if (remote == nullptr) {
        PINAUTH_HILOGE(MODULE_SERVICE, "PinAuthManager::OnRemoteDied remote is nullptr");
        return;
    }
    PinAuthManager::GetInstance().UnRegisterInputer(uid_);
}
} // namespace PinAuth
} // namespace UserIAM
} // namespace OHOS
