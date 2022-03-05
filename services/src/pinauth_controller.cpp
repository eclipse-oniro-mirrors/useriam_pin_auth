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

#include "pinauth_controller.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "coauth_info_define.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "parameter.h"
#include "pinauth_defines.h"
#include "pinauth_log_wrapper.h"

namespace OHOS {
namespace UserIAM {
namespace PinAuth {
PinAuthController::PinAuthController()
{
    attributes_ = nullptr;
    pin_ = nullptr;
}

PinAuthController::~PinAuthController()
{
    attributes_ = nullptr;
    pin_ = nullptr;
}

bool PinAuthController::OnStart(std::vector<uint8_t> &salt)
{
    int32_t ret = attributes_->GetUint32Value(AUTH_SCHEDULE_MODE, command_);
    if (ret != SUCCESS) {
        PINAUTH_HILOGE(MODULE_SERVICE, "PinAuthController::OnStart GetUint32Value AUTH_SCHEDULE_MODE error");
        return false;
    }
    if (command_ == COMMAND_ENROLL_PIN) {
        NewSalt(salt);
        PINAUTH_HILOGI(MODULE_COMMON, "EnrollPin finish");
    } else if (command_ == COMMAND_AUTH_PIN) {
        ret = attributes_->GetUint64Value(AUTH_TEMPLATE_ID, templateId_);
        if (ret != SUCCESS) {
            PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthController::OnStart GetUint64Value AUTH_TEMPLATE_ID error");
            return false;
        }
        ret = pin_->GetSalt(templateId_, salt);
        if (ret != SUCCESS) {
            PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthController::OnStart GetSalt error");
            return false;
        }
    }
    PINAUTH_HILOGI(MODULE_COMMON, "AuthPin finish");
    salt_ = salt;
    return true;
}

void PinAuthController::OnSetData(int32_t authSubType, std::vector<uint8_t> data)
{
    PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthController::OnSetData enter");
    std::lock_guard<std::mutex> guard(mutex_);
    if (canceled) {
        PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthController::onSetData event has canceled");
        return;
    }

    PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthController::onSetData data size is : [%{public}zu]", data.size());
    int32_t ret = SUCCESS;
    if (data.size() == 0) {
        PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthController::onSetData data is null");
        ret = FAIL;
    }

    auto finalResult = std::make_shared<AuthResPool::AuthAttributes>();
    std::vector<uint8_t> result;
    if (ret == SUCCESS) {
        if (command_ == COMMAND_ENROLL_PIN) {
            PINAUTH_HILOGE(MODULE_SERVICE, "PinAuthController::onSetData command == COMMAND_ENROLL_PIN");
            ret = pin_->EnrollPin(scheduleId_, static_cast<uint64_t>(authSubType), salt_, data, result);
            PINAUTH_HILOGI(MODULE_COMMON, "---------EnrollPin finish----------");
        } else if (command_ == COMMAND_AUTH_PIN) {
            PINAUTH_HILOGE(MODULE_SERVICE, "PinAuthController::onSetData command == COMMAND_AUTH_PIN");
            ret = pin_->AuthPin(scheduleId_, templateId_, data, result);
            PINAUTH_HILOGI(MODULE_COMMON, "----------AuthPin finish %{public}d-----------", ret);
        }
    }

    PINAUTH_HILOGI(MODULE_COMMON, "PinAuthController::onSetData finalResult is Unpack");
    finalResult->SetUint8ArrayValue(AUTH_RESULT, result);
    if (messenger_ != nullptr) {
        int32_t sendRet = messenger_->Finish(scheduleId_, PIN, ret, finalResult);
        if (sendRet != SUCCESS) {
            PINAUTH_HILOGE(MODULE_SERVICE, "PinAuthController::onSetData call finish failed");
        }
    } else {
        PINAUTH_HILOGE(MODULE_COMMON, "PinAuthController::onSetData messenger_ is null");
    }

    PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthController::OnSetData leave");
}

void PinAuthController::SaveParam(uint64_t scheduleId, std::shared_ptr<PinAuth> pin,
    std::shared_ptr<AuthResPool::AuthAttributes> attributes)
{
    std::lock_guard<std::mutex> guard(mutex_);
    PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthController::SaveParam enter");
    scheduleId_ = scheduleId;
    pin_ = pin;
    attributes_ = attributes;
}

void PinAuthController::SetMessenger(const sptr<AuthResPool::IExecutorMessenger> &messenger)
{
    PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthController::SetMessenger enter");
    std::lock_guard<std::mutex> guard(mutex_);
    messenger_ = messenger;
}

void PinAuthController::Cancel()
{
    PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthController::Cancel enter");
    std::lock_guard<std::mutex> guard(mutex_);
    canceled = true;
}

void NewSalt(std::vector<uint8_t> &saltV)
{
    char localDeviceId[DEVICE_UUID_LENGTH] = {0};
    GetDevUdid(localDeviceId, DEVICE_UUID_LENGTH);
    unsigned char random[RANDOM_LENGTH] = {0};
    RAND_bytes(random, (int)RANDOM_LENGTH);
    std::vector<uint8_t> sum;
    for (uint32_t i = 0; i < DEVICE_UUID_LENGTH; i++) {
        sum.push_back(localDeviceId[i]);
    }
    for (uint32_t i = 0; i < RANDOM_LENGTH; i++) {
        sum.push_back(random[i]);
    }
    const EVP_MD *alg = EVP_sha256();
    PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthController::NewSalt EVP_sha256 success");
    uint32_t size;
    uint8_t result[SHA256_LENGTH] = {0};
    EVP_Digest(sum.data(), sum.size(), result, &size, alg, NULL);
    for (uint32_t i = 0; i < size; i++) {
        saltV.push_back(result[i]);
    }
    PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthController::NewSalt result size is : [%{public}u]", size);
}
} // namespace PinAuth
} // namespace UserIAM
} // namespace OHOS
