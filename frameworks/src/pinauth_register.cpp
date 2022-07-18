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

#include "pinauth_register.h"

#include <if_system_ability_manager.h>
#include <iservice_registry.h>
#include <system_ability_definition.h>

#include "refbase.h"
#include "iremote_broker.h"
#include "iremote_object.h"

#include "pinauth_log_wrapper.h"
#include "i_inputer_stub.h"
#include "iremote_inputer.h"
#include "iremote_pinauth.h"

namespace OHOS {
namespace UserIAM {
namespace PinAuth {
PinAuthRegister::PinAuthRegister() = default;
PinAuthRegister::~PinAuthRegister() = default;

bool PinAuthRegister::RegisterInputer(std::shared_ptr<IInputer> inputer)
{
    PINAUTH_HILOGI(MODULE_INNERKIT, "PinAuthRegister::RegisterInputer start");
    if (inputer == nullptr) {
        PINAUTH_HILOGE(MODULE_INNERKIT, "inputer is nullptr");
        return false;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        PINAUTH_HILOGE(MODULE_INNERKIT, "get proxy failed");
        return false;
    }
    sptr<IRemoteInputer> callback = new IInputerStub(inputer);
    if (callback == nullptr) {
        return false;
    }
    return proxy->RegisterInputer(callback);
}

void PinAuthRegister::UnRegisterInputer()
{
    PINAUTH_HILOGI(MODULE_INNERKIT, "PinAuthRegister::UnRegisterInputer start");
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        PINAUTH_HILOGE(MODULE_INNERKIT, "pinAuth failed, remote is nullptr");
        return;
    }
    proxy->UnRegisterInputer();
}

sptr<IRemotePinAuth> PinAuthRegister::GetProxy()
{
    PINAUTH_HILOGI(MODULE_INNERKIT, "PinAuthRegister::GetProxy start");
    if (proxy_ != nullptr) {
        return proxy_;
    }
    sptr<ISystemAbilityManager> sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        PINAUTH_HILOGE(MODULE_INNERKIT, "Failed to get system ability manager");
        return nullptr;
    }
    sptr<IRemoteObject> obj = sam->CheckSystemAbility(SUBSYS_USERIAM_SYS_ABILITY_PINAUTH);
    if (obj == nullptr) {
        PINAUTH_HILOGE(MODULE_INNERKIT, "Failed to get distributed gallery manager service");
        return nullptr;
    }
    sptr<IRemoteObject::DeathRecipient> dr = new PinAuthDeathRecipient();
    if ((obj->IsProxyObject()) && (!obj->AddDeathRecipient(dr))) {
        PINAUTH_HILOGE(MODULE_INNERKIT, "Failed to add death recipient");
        return nullptr;
    }

    proxy_ = iface_cast<IRemotePinAuth>(obj);
    deathRecipient_ = dr;
    PINAUTH_HILOGI(MODULE_INNERKIT, "Succeed to connect distributed gallery manager service");
    return proxy_;
}

void PinAuthRegister::ResetProxy(const wptr<IRemoteObject>& remote)
{
    PINAUTH_HILOGI(MODULE_INNERKIT, "PinAuthRegister::ResetProxy start");
    std::lock_guard<std::mutex> lock(mutex_);
    auto serviceRemote = proxy_->AsObject();
    if ((serviceRemote != nullptr) && (serviceRemote == remote.promote())) {
        serviceRemote->RemoveDeathRecipient(deathRecipient_);
        proxy_ = nullptr;
    }
}

void PinAuthRegister::PinAuthDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& remote)
{
    PINAUTH_HILOGI(MODULE_INNERKIT, "PinAuthRegister::OnRemoteDied start");
    if (remote == nullptr) {
        PINAUTH_HILOGE(MODULE_INNERKIT, "OnRemoteDied failed, remote is nullptr");
        return;
    }
    PinAuthRegister::GetInstance().ResetProxy(remote);
    PINAUTH_HILOGI(MODULE_INNERKIT, "PinAuthDeathRecipient::Recv death notice");
}
} // namespace PinAuth
} // namespace UserIAM
} // namespace OHOS