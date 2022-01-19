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

#include "pinauth_service.h"
#include "pinauth_log_wrapper.h"
#include "pinauth_defines.h"
#include "pinauth_controller.h"
#include "pinauth_manager.h"
#include "coauth_info_define.h"

namespace OHOS {
namespace UserIAM {
namespace PinAuth {
const uint64_t INVALID_EXECUTOR_ID = 0;
const bool REGISTER_RESULT =
    SystemAbility::MakeAndRegisterAbility(DelayedSingleton<PinAuthService>::GetInstance().get());

PinAuthService::PinAuthService()
    : SystemAbility(SUBSYS_USERIAM_SYS_ABILITY_PINAUTH, true),
      serviceRunningState_(ServiceRunningState::STATE_NOT_START)
{
}

PinAuthService::~PinAuthService()
{
}

void PinAuthService::OnStart()
{
    PINAUTH_HILOGD(MODULE_SERVICE, "PinAuthService::OnStart");
    executor_ = std::make_shared<AuthResPool::AuthExecutor>();
    mngIQ_ = std::make_shared<MngIQCallback>(this);
    mngEx_ = std::make_shared<MngExCallback>(this);
    pin_ = std::make_shared<PinAuth>();
    if (!pin_->Init()) {
        PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthService::InitPinAuth");
    }
    ActuatorInfoQuery();
    PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthService: Query executor status");
    PinAuthManager::GetInstance().MapClear();
    if (!Publish(this)) {
        PINAUTH_HILOGE(MODULE_SERVICE, "failed to publish the service.");
        return;
    }

    serviceRunningState_ = ServiceRunningState::STATE_RUNNING;
    PINAUTH_HILOGI(MODULE_SERVICE, "End");
}

void PinAuthService::OnStop()
{
    PINAUTH_HILOGI(MODULE_SERVICE, "Start");
    if (!pin_->Close()) {
        PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthController::ClosePinAuth");
    }
    serviceRunningState_ = ServiceRunningState::STATE_NOT_START;
    PINAUTH_HILOGI(MODULE_SERVICE, "End");
}

bool PinAuthService::RegisterInputer(sptr<IRemoteInputer> inputer)
{
    PINAUTH_HILOGD(MODULE_SERVICE, "PinAuthService::RegisterInputer enter");
    if (inputer == nullptr) {
        PINAUTH_HILOGD(MODULE_SERVICE, "PinAuthService::RegisterInputer inputer == nullptr");
        return false;
    }
    // return PinAuthManager::GetInstance().RegisterInputer(GetCallingUid(), inputer);
    return PinAuthManager::GetInstance().RegisterInputer(0, inputer);
}

void PinAuthService::UnRegisterInputer()
{
    PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthService::UnRegisterInputer enter");
    // PinAuthManager::GetInstance().UnRegisterInputer(GetCallingUid());
    PinAuthManager::GetInstance().UnRegisterInputer(0);
}

void PinAuthService::ActuatorInfoQuery()
{
    PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthService::ActuatorInfoQuery enter");
    uint32_t esl;
    uint64_t authAbility;
    std::vector<uint8_t> pubKey;
    if (pin_->GetExecutorInfo(pubKey, esl, authAbility) != SUCCESS) {
        PINAUTH_HILOGE(MODULE_SERVICE, "PinAuthService::OnResult GetExecutorInfo");
        return;
    }

    if (executor_->SetAuthType(PIN) != SUCCESS) {
        PINAUTH_HILOGE(MODULE_SERVICE, "PinAuthService::OnResult SetAuthType");
        return;
    }

    if (executor_->SetAuthAbility(authAbility) != SUCCESS) {
        PINAUTH_HILOGE(MODULE_SERVICE, "PinAuthService::OnResult SetAuthAbility");
        return;
    }

    if (executor_->SetExecutorSecLevel(static_cast<ExecutorSecureLevel>(esl)) != SUCCESS) {
        PINAUTH_HILOGE(MODULE_SERVICE, "PinAuthService::OnResult SetExecutorSecLevel");
        return;
    }

    if (executor_->SetExecutorType(TYPE_ALL_IN_ONE) != SUCCESS) {
        PINAUTH_HILOGE(MODULE_SERVICE, "PinAuthService::OnResult SetExecutorType");
        return;
    }

    if (executor_->SetPublicKey(pubKey) != SUCCESS) {
        PINAUTH_HILOGE(MODULE_SERVICE, "PinAuthService::OnResult SetPublicKey");
        return;
    }
    AuthResPool::AuthExecutorRegistry::GetInstance().QueryStatus(*executor_, mngIQ_);
}

void PinAuthService::OnResult(uint32_t resultCode)
{
    PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthService::OnResult enter");
    /* Has been registered */
    if (resultCode == SUCCESS) {
        PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthService::OnResult resultCode == SUCCESS");
        return;
    }
    // To do register
    executorID_ = AuthResPool::AuthExecutorRegistry::GetInstance().Register(executor_, mngEx_);
    if (executorID_ == INVALID_EXECUTOR_ID) {
        PINAUTH_HILOGE(MODULE_SERVICE, "Executor register fail");
    }
}

int32_t PinAuthService::OnBeginExecute(uint64_t scheduleId, std::vector<uint8_t> &publicKey,
                                       std::shared_ptr<AuthAttributes> commandAttrs)
{
    PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthService::OnBeginExecute enter");

    if (commandAttrs == nullptr) {
        PINAUTH_HILOGE(MODULE_SERVICE, "PinAuthService::OnBeginExecute commandAttrs nullptr");
        return FAIL;
    }
    uint64_t subType;
    if (commandAttrs->GetUint64Value(AUTH_SUBTYPE, subType) != SUCCESS) {
        PINAUTH_HILOGE(MODULE_SERVICE, "PinAuthService::OnBeginExecute AUTH_SUBTYPE");
        return FAIL;
    }
    uint64_t callerUid;
    if (commandAttrs->GetUint64Value(AUTH_CALLER_UID, callerUid) != SUCCESS) {
        PINAUTH_HILOGE(MODULE_SERVICE, "PinAuthService::OnBeginExecute AUTH_CALLER_UID");
        return FAIL;
    }
    PinAuthManager::GetInstance().Execute(callerUid, subType, scheduleId, pin_, commandAttrs);
    PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthService::OnBeginExecute uid %{public}llu is called.", callerUid);
    return SUCCESS;
}

int32_t PinAuthService::OnEndExecute(uint64_t scheduleId, std::shared_ptr<AuthAttributes> consumerAttr)
{
    PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthService::OnEndExecute enter");
    PinAuthManager::GetInstance().Cancel(scheduleId, consumerAttr);
    return SUCCESS;
}
bool PinAuthService::IsUserIDM(uint64_t callerUid)
{
    /* todo */
    return true;
}
int32_t PinAuthService::OnSetProperty(std::shared_ptr<AuthAttributes> properties)
{
    PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthService::OnSetProperty enter");
    if (properties == nullptr) {
        PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthService::OnSetProperty properties nullptr");
        return FAIL;
    }
    /* get command 0:pin delete 1:Query credential information */
    uint32_t command;
    if (properties->GetUint32Value(AUTH_PROPERTY_MODE, command) != SUCCESS) {
        PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthService::OnSetProperty GetUint32Value");
        return FAIL;
    }

    uint64_t callerUid;
    if (properties->GetUint64Value(AUTH_CALLER_UID, callerUid) != SUCCESS) {
        PINAUTH_HILOGE(MODULE_SERVICE, "PinAuthService::OnSetProperty AUTH_CALLER_UID");
        return FAIL;
    }

    if (command == COMMAND_DELETE_PIN && IsUserIDM(callerUid)) {
        /* get templateId */
        uint64_t templateId;
        if (properties->GetUint64Value(AUTH_TEMPLATE_ID, templateId) != SUCCESS) {
            PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthService::OnSetProperty GetUint64Value AUTH_TEMPLATE_ID");
            return FAIL;
        }
        /* PIN delete */
        int32_t res = pin_->DeleteTemplate(templateId);
        PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthService::OnSetProperty DeleteTemplate");
        /* return result */
        if (properties->SetUint32Value(AUTH_RESULT_CODE, res) != SUCCESS) {
            PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthService::OnSetProperty SetUint32Value");
            return FAIL;
        }
        if (!res) {
            PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthService::OnSetProperty DeleteTemplate");
            return FAIL;
        }
    } else {
        PINAUTH_HILOGI(MODULE_SERVICE,
                     "PinAuthService::OnSetProperty !(command == COMMAND_DELETE_PIN && IsUserIDM(callerUid))");
        return FAIL;
    }
    return SUCCESS;
}

int32_t PinAuthService::OnGetProperty(std::shared_ptr<AuthResPool::AuthAttributes> conditions,
                                      std::shared_ptr<AuthResPool::AuthAttributes> values)
{
    PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthService::OnGetProperty enter");
    if (values == nullptr) {
        PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthService::OnGetProperty values nullptr");
        return FAIL;
    }

    /* set command 0:pin delete 1:Query credential information */
    uint32_t command;
    if (conditions->GetUint32Value(AUTH_PROPERTY_MODE, command) != SUCCESS) {
        PINAUTH_HILOGI(MODULE_SERVICE, "___PinAuthService::OnGetProperty GetUint32Value___");
        return FAIL;
    }
    PINAUTH_HILOGD(MODULE_SERVICE, 
                 "___PinAuthService::OnBeginExecute AUTH_PROPERTY_MODE is %{public}d ##########.", command);
    if (command == COMMAND_CHECK_PIN) {
        /* get templateId */
        uint64_t templateId;
        if (conditions->GetUint64Value(AUTH_TEMPLATE_ID, templateId) != SUCCESS) {
            PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthService::OnGetProperty GetUint64Value");
            return FAIL;
        }

        /* Query credential information */
        PinCredentialInfo info;
        pin_->QueryPinInfo(templateId, info);
        if (values->SetUint64Value(AUTH_SUBTYPE, info.subType) != SUCCESS) {
            PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthService::OnGetProperty SetUint64Value");
            return FAIL;
        }
        /* send remainTimes FreezingTime */
        if (values->SetUint32Value(AUTH_REMAIN_TIME, static_cast<uint32_t>(info.freezingTime))) {
            PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthService::OnGetProperty SetUint32ArrayValue");
            return FAIL;
        }

        if (values->SetUint32Value(AUTH_REMAIN_COUNT, static_cast<uint32_t>(info.remainTimes))) {
            PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthService::OnGetProperty SetUint32ArrayValue");
            return FAIL;
        }
    }
    return SUCCESS;
}

void PinAuthService::OnMessengerReady(const sptr<IExecutorMessenger> &messenger)
{
    PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthService::OnMessengerReady enter");
    PinAuthManager::GetInstance().SetMessenger(messenger);
}
} // namespace PinAuth
} // namespace UserIAM
} // namespace OHOS
