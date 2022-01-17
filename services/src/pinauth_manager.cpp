/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "pinauth_log_wrapper.h"

namespace OHOS {
namespace UserIAM {
namespace PinAuth {
PinAuthManager::PinAuthManager() = default;
PinAuthManager::~PinAuthManager() = default;
bool PinAuthManager::RegisterInputer(uint64_t uid, sptr<IRemoteInputer> &inputer)
{
    std::lock_guard<std::mutex> guard(mutex_);
    PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthManager::RegisterInputer uid%{public}llu is called.", uid);
    if (pinAuthInputerMap_.find(uid) != pinAuthInputerMap_.end()) {
        PINAUTH_HILOGE(MODULE_SERVICE,
                     "PinAuthManager::RegisterInputer pinAuthController is already register, do not repeat!");
        return false;
    } else {
        pinAuthInputerMap_.emplace(uid, inputer);
        PINAUTH_HILOGE(MODULE_SERVICE, "PinAuthManager::RegisterInputer pinAuthController register start!");
        return true;
    }
}

void PinAuthManager::UnRegisterInputer(uint64_t uid)
{
    std::lock_guard<std::mutex> guard(mutex_);
    PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthManager::UnRegisterInputer uid%{public}llu is called start", uid);
    pinAuthInputerMap_.erase(uid);
    PINAUTH_HILOGI(MODULE_SERVICE, "pinAuthControllerMap erase success.");
    PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthManager::UnRegisterInputer() is called end.");
}

void PinAuthManager::Execute(uint64_t uid, uint64_t subType, uint64_t scheduleId, std::shared_ptr<PinAuth> pin,
                             std::shared_ptr<AuthResPool::AuthAttributes> attributes)
{
    PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthManager::Execute uid %{public}llu is called.", uid);
    sptr<IRemoteInputer> inputer = getInputerLock(uid);
    if (inputer != nullptr) {
        sptr<PinAuthController> controller = new PinAuthController();
        controller->SetMessenger(messenger_);
        controller->SaveParam(scheduleId, pin, attributes);
        setPinAuthControllerLock(scheduleId, controller);
        std::vector<uint8_t> salt;
        bool sResult = controller->OnStart(salt);
        PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthManager::Excute salt is : [%{public}s]" , salt.data());
        if (sResult) {
            PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthManager::Excute OnStart SUCCESS CALL OnGetData");
            inputer->OnGetData(subType, salt, controller);
            return;
        }
    } else {
        PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthManager::Execute inputer is nullptr !");
    }
    auto finalResult = std::make_shared<AuthResPool::AuthAttributes>();
    std::vector<uint8_t> result;
    finalResult->Unpack(result);
    messenger_->Finish(scheduleId, PIN, FAIL, finalResult);
}

int32_t PinAuthManager::Cancel(uint64_t scheduleId, std::shared_ptr<AuthResPool::AuthAttributes> consumerAttr)
{
    PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthManager::Cancel start");
    sptr<PinAuthController> controller = getPinAuthControllerLock(scheduleId);
    if (controller != nullptr) {
        controller->Cancel();
        std::lock_guard<std::mutex> guard(mutex_);
        pinAuthConMap_.erase(scheduleId);
        return SUCCESS;
    } else {
        PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthManager::Cancel pinAuthController is nullptr !");
    }
    return FAIL;
}

void PinAuthManager::SetMessenger(const sptr<AuthResPool::IExecutorMessenger> &messenger)
{
    PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthManager::SetMessenger()");
    messenger_ = messenger;
}

void PinAuthManager::MapClear()
{
    PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthManager::MapClear()");
    std::lock_guard<std::mutex> guard(mutex_);
    pinAuthInputerMap_.clear();
}

sptr<PinAuthController> PinAuthManager::getPinAuthControllerLock(uint64_t scheduleId)
{
    std::lock_guard<std::mutex> guard(mutex_);
    auto pinAuthController = pinAuthConMap_.find(scheduleId);
    if (pinAuthController != pinAuthConMap_.end()) {
        PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthManager::getPinAuthController() has pinAuthController");
        return pinAuthController->second;
    } else {
        PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthManager::getPinAuthController pinAuthController is not found!!!");
    }
    return nullptr;
}

void PinAuthManager::setPinAuthControllerLock(uint64_t scheduleId, sptr<PinAuthController> controller)
{
    std::lock_guard<std::mutex> guard(mutex_);
    pinAuthConMap_.emplace(scheduleId, controller);
}

sptr<IRemoteInputer> PinAuthManager::getInputerLock(uint64_t uid)
{
    std::lock_guard<std::mutex> guard(mutex_);
    auto pinAuthInputer = pinAuthInputerMap_.find(uid);
    if (pinAuthInputer != pinAuthInputerMap_.end()) {
        PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthManager::getInputer() has pinAuthInputer");
        return pinAuthInputer->second;
    } else {
        PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthManager::getInputer pinAuthInputer is not found!!!");
    }
    return nullptr;
}
} // namespace PinAuth
} // namespace UserIAM
} // namespace OHOS