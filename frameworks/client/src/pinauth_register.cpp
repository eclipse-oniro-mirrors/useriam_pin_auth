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

#include "inputer_get_data_service.h"
#include "inputer_get_data.h"
#include "iam_logger.h"

#define LOG_LABEL OHOS::UserIam::Common::LABEL_PIN_AUTH_SDK

namespace OHOS {
namespace UserIam {
namespace PinAuth {
PinAuthRegister::PinAuthRegister() = default;
PinAuthRegister::~PinAuthRegister() = default;

bool PinAuthRegister::RegisterInputer(std::shared_ptr<IInputer> inputer)
{
    IAM_LOGI("start");
    if (inputer == nullptr) {
        IAM_LOGE("inputer is nullptr");
        return false;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        IAM_LOGE("get proxy failed");
        return false;
    }
    sptr<InputerGetData> callback = new (std::nothrow) InputerGetDataService(inputer);
    if (callback == nullptr) {
        return false;
    }
    return proxy->RegisterInputer(callback);
}

void PinAuthRegister::UnRegisterInputer()
{
    IAM_LOGI("start");
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        IAM_LOGE("proxy is nullptr");
        return;
    }
    proxy->UnRegisterInputer();
}

sptr<PinAuthInterface> PinAuthRegister::GetProxy()
{
    IAM_LOGI("start");
    if (proxy_ != nullptr) {
        return proxy_;
    }
    sptr<ISystemAbilityManager> sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        IAM_LOGE("get system ability manager fail");
        return nullptr;
    }
    sptr<IRemoteObject> obj = sam->CheckSystemAbility(SUBSYS_USERIAM_SYS_ABILITY_PINAUTH);
    if (obj == nullptr) {
        IAM_LOGE("get distributed gallery manager service fail");
        return nullptr;
    }
    sptr<IRemoteObject::DeathRecipient> dr = new PinAuthDeathRecipient();
    if ((obj->IsProxyObject()) && (!obj->AddDeathRecipient(dr))) {
        IAM_LOGE("add death recipient fail");
        return nullptr;
    }

    proxy_ = iface_cast<PinAuthInterface>(obj);
    deathRecipient_ = dr;
    IAM_LOGI("succeed to connect distributed gallery manager service");
    return proxy_;
}

void PinAuthRegister::ResetProxy(const wptr<IRemoteObject>& remote)
{
    IAM_LOGI("start");
    std::lock_guard<std::mutex> lock(mutex_);
    auto serviceRemote = proxy_->AsObject();
    if ((serviceRemote != nullptr) && (serviceRemote == remote.promote())) {
        serviceRemote->RemoveDeathRecipient(deathRecipient_);
        proxy_ = nullptr;
    }
}

void PinAuthRegister::PinAuthDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& remote)
{
    IAM_LOGI("start");
    if (remote == nullptr) {
        IAM_LOGE("remote is nullptr");
        return;
    }
    PinAuthRegister::GetInstance().ResetProxy(remote);
    IAM_LOGI("recv death notice");
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS