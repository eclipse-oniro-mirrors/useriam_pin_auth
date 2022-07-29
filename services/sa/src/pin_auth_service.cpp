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

#include "pin_auth_service.h"

#include <cinttypes>

#include "accesstoken_kit.h"
#include "parameter.h"
#include "i_inputer_data_impl.h"
#include "iam_check.h"
#include "iam_common_defines.h"
#include "iam_logger.h"
#include "iam_para2str.h"
#include "iam_ptr.h"
#include "idriver_manager.h"
#include "pinauth_driver_hdi.h"
#include "pinauth_manager.h"


#define LOG_LABEL UserIam::Common::LABEL_PIN_AUTH_SA

namespace OHOS {
namespace UserIam {
namespace PinAuth {
namespace {
    const std::string ACCESS_PIN_AUTH = "ohos.permission.ACCESS_PIN_AUTH";
    const bool REGISTER_RESULT = SystemAbility::MakeAndRegisterAbility(PinAuthService::GetInstance().get());
} // namespace
std::mutex PinAuthService::mutex_;
std::shared_ptr<PinAuthService> PinAuthService::instance_ = nullptr;

PinAuthService::PinAuthService() : SystemAbility(SUBSYS_USERIAM_SYS_ABILITY_PINAUTH, true)
{
}

std::shared_ptr<PinAuthService> PinAuthService::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> gurard(mutex_);
        if (instance_ == nullptr) {
            instance_ = Common::MakeShared<PinAuthService>();
            if (instance_ == nullptr) {
                IAM_LOGE("make share failed");
            }
        }
    }
    return instance_;
}

void PinAuthService::OnStart()
{
    IAM_LOGI("start");
    StartDriverManager();
    if (!Publish(this)) {
        IAM_LOGE("failed to publish pin auth service");
        return;
    }
}

void PinAuthService::OnStop()
{
    IAM_LOGE("service is persistent, OnStop is not implemented");
}

inline uint32_t PinAuthService::GetTokenId()
{
    uint32_t tokenId = this->GetFirstTokenID();
    if (tokenId == 0) {
        tokenId = this->GetCallingTokenID();
    }
    return tokenId;
}

void PinAuthService::StartDriverManager()
{
    IAM_LOGI("start");
    auto pinAuthDefaultHdi = Common::MakeShared<PinAuthDriverHdi>();
    IF_FALSE_LOGE_AND_RETURN(pinAuthDefaultHdi != nullptr);
    const uint16_t pinAuthDefaultHdiId = 1;
    // serviceName and HdiConfig.id must be globally unique
    const std::map<std::string, UserIam::UserAuth::HdiConfig> hdiName2Config  = {
        {"pin_auth_interface_service", {pinAuthDefaultHdiId, pinAuthDefaultHdi}},
    };
    int ret = UserIam::UserAuth::IDriverManager::Start(hdiName2Config);
    if (ret != UserAuth::SUCCESS) {
        IAM_LOGE("start driver manager failed");
    }
}

bool PinAuthService::CheckPermission(const std::string &permission)
{
    IAM_LOGI("start");
    using namespace Security::AccessToken;
    uint32_t tokenId = GetTokenId();
    return AccessTokenKit::VerifyAccessToken(tokenId, permission) == RET_SUCCESS;
}

bool PinAuthService::RegisterInputer(sptr<IRemoteInputer> inputer)
{
    IAM_LOGI("start");
    if (!CheckPermission(ACCESS_PIN_AUTH)) {
        IAM_LOGE("failed to check permission");
        return false;
    }
    if (inputer == nullptr) {
        IAM_LOGE("inputer is nullptr");
        return false;
    }
    uint32_t tokenId = GetTokenId();
    return PinAuthManager::GetInstance().RegisterInputer(tokenId, inputer);
}

void PinAuthService::UnRegisterInputer()
{
    IAM_LOGI("start");
    if (!CheckPermission(ACCESS_PIN_AUTH)) {
        IAM_LOGE("failed to check permission");
        return;
    }
    uint32_t tokenId = GetTokenId();
    PinAuthManager::GetInstance().UnRegisterInputer(tokenId);
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
