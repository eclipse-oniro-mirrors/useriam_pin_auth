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

#include "pinauth_service.h"
#include <cinttypes>
#include "accesstoken_kit.h"
#include "parameter.h"
#include "i_inputter_data_impl.h"
#include "pinauth_log_wrapper.h"
#include "pinauth_manager.h"

namespace OHOS {
namespace UserIAM {
namespace PinAuth {
static const std::string ACCESS_PIN_AUTH = "ohos.permission.ACCESS_PIN_AUTH";
static const char IAM_EVENT_KEY[] = "bootevent.useriam.fwkready";
const bool REGISTER_RESULT =
    SystemAbility::MakeAndRegisterAbility(PinAuthService::GetInstance().get());
std::mutex PinAuthService::mutex_;
std::shared_ptr<PinAuthService> PinAuthService::instance_ = nullptr;

PinAuthService::PinAuthService() : SystemAbility(SUBSYS_USERIAM_SYS_ABILITY_PINAUTH, true) {}

std::shared_ptr<PinAuthService> PinAuthService::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock_l(mutex_);
        if (instance_ == nullptr) {
            instance_ = std::make_shared<PinAuthService>();
        }
    }
    return instance_;
}

void PinAuthService::OnStart()
{
    PINAUTH_HILOGI(MODULE_SERVICE, "start");
    auto eventCallback = [](const char *key, const char *value, void *context) {
    PINAUTH_HILOGI(MODULE_SERVICE, "receive useriam.fwkready event");
     if (key == nullptr || value == nullptr) {
         PINAUTH_HILOGE(MODULE_SERVICE, "param is null");
        return;
    }
    if (strcmp(key, IAM_EVENT_KEY) != 0) {
        PINAUTH_HILOGE(MODULE_SERVICE, "event key mismatch");
        return;
    }
    if (strcmp(value, "true")) {
        PINAUTH_HILOGI(MODULE_SERVICE, "event value is not true");
        return;
    }
    PinAuthService::GetInstance()->RegisterResourcePool();
    };
    WatchParameter(IAM_EVENT_KEY, eventCallback, nullptr);
    ConfigDriverManager();
    StartDriverManager();
    PINAUTH_HILOGI(MODULE_SERVICE, "success");
}

void PinAuthService::OnStop()
{
    PINAUTH_HILOGI(MODULE_SERVICE, "start");
    StopDriverManager();
}

void PinAuthService::RegisterResourcePool()
{
    PINAUTH_HILOGI(MODULE_SERVICE, "start");
    OHOS::UserIAM::UserAuth::DriverManager::GetInstance()->RegisterResourcePool();
}

void PinAuthService::ConfigDriverManager()
{
    PINAUTH_HILOGI(MODULE_SERVICE, "start");
    std::map<std::string, UserAuth::ServiceConfig> serviceName2Config = {
        { "pin_auth_interface_service", { 1, std::make_shared<PinAuthHDIFactory>() }},
    };
    OHOS::UserIAM::UserAuth::DriverManager::GetInstance()->Config(serviceName2Config);
}

void PinAuthService::StartDriverManager()
{
    PINAUTH_HILOGI(MODULE_SERVICE, "start");
    OHOS::UserIAM::UserAuth::DriverManager::GetInstance()->Start();
}

void PinAuthService::StopDriverManager()
{
    PINAUTH_HILOGI(MODULE_SERVICE, "start");
    OHOS::UserIAM::UserAuth::DriverManager::GetInstance()->Stop();
}

bool PinAuthService::CheckPermission(const std::string &permission)
{
    PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthService::CheckPermission start");
    using namespace Security::AccessToken;
    uint32_t tokenID = this->GetFirstTokenID();
    if (tokenID == 0) {
        tokenID = this->GetCallingTokenID();
    }
    return AccessTokenKit::VerifyAccessToken(tokenID, permission) == RET_SUCCESS;
}

bool PinAuthService::RegisterInputer(sptr<IRemoteInputer> inputer)
{
    PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthService::RegisterInputer start");
    if (!CheckPermission(ACCESS_PIN_AUTH)) {
        PINAUTH_HILOGE(MODULE_SERVICE, "Permission check failed");
        return false;
    }
    if (inputer == nullptr) {
        PINAUTH_HILOGE(MODULE_SERVICE, "PinAuthService::RegisterInputer inputer == nullptr");
        return false;
    }
    return PinAuthManager::GetInstance().RegisterInputer(GetCallingUid(), inputer);
}

void PinAuthService::UnRegisterInputer()
{
    PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthService::UnRegisterInputer start");
    if (!CheckPermission(ACCESS_PIN_AUTH)) {
        PINAUTH_HILOGE(MODULE_SERVICE, "Permission check failed");
        return;
    }
    PinAuthManager::GetInstance().UnRegisterInputer(GetCallingUid());
}

} // namespace PinAuth
} // namespace UserIAM
} // namespace OHOS
