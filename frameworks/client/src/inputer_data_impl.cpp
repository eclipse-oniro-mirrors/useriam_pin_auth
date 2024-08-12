/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "inputer_data_impl.h"

#include <cstddef>
#include <regex>
#include <vector>

#include <openssl/sha.h>

#include "securec.h"

#include "iam_logger.h"
#include "iam_ptr.h"
#include "scrypt.h"
#include "settings_data_manager.h"
#ifdef CUSTOMIZATION_ENTERPRISE_DEVICE_MANAGEMENT_ENABLE
#include "security_manager_proxy.h"
#endif

#define LOG_TAG "PIN_AUTH_SDK"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
namespace {
constexpr uint32_t MIN_PIN_LENGTH = 4;
}

InputerDataImpl::InputerDataImpl(const InputerGetDataParam &param)
    : mode_(param.mode), algoVersion_(param.algoVersion), algoParameter_(param.algoParameter),
      inputerSetData_(param.inputerSetData), complexityReg_(param.complexityReg), userId_(param.userId)
{
}

void InputerDataImpl::GetRecoveryKeyData(
    const std::vector<uint8_t> &dataIn, std::vector<uint8_t> &dataOut, int32_t &errorCode)
{
    if (algoVersion_ == RECOVERY_KEY_ALGO_VERSION_V0) {
        if (GetSha256(dataIn, dataOut)) {
            IAM_LOGI("recovery key data sha256 succeed");
            errorCode = UserAuth::SUCCESS;
            return;
        }
    }
    IAM_LOGE("recovery key data sha256 failed");
}

void InputerDataImpl::GetPinData(
    int32_t authSubType, const std::vector<uint8_t> &dataIn, std::vector<uint8_t> &dataOut, int32_t &errorCode)
{
    errorCode = CheckPinComplexity(authSubType, dataIn);
    if (errorCode != UserAuth::SUCCESS && mode_ == GET_DATA_MODE_ALL_IN_ONE_PIN_ENROLL) {
        IAM_LOGE("CheckPinComplexity enroll failed");
        return;
    }

    if (mode_ == GET_DATA_MODE_ALL_IN_ONE_PIN_ENROLL && authSubType == UserAuth::PIN_PATTERN) {
        IAM_LOGE("GetPinData Enroll Unsupport Type Pattern");
        return;
    }
    auto scryptPointer = Common::MakeUnique<Scrypt>(algoParameter_);
    if (scryptPointer == nullptr) {
        IAM_LOGE("scryptPointer is nullptr");
        return;
    }
    if (authSubType == UserAuth::PIN_PATTERN) {
        std::vector<uint8_t> patternDataIn(dataIn);
        for (uint8_t &data : patternDataIn) {
            data += 1;
        }
        scryptPointer->GetScrypt(patternDataIn, algoVersion_).swap(dataOut);
        (void)memset_s(patternDataIn.data(), patternDataIn.size(), 0, patternDataIn.size());
    } else {
        scryptPointer->GetScrypt(dataIn, algoVersion_).swap(dataOut);
    }
    if (dataOut.empty()) {
        IAM_LOGE("get scrypt fail");
        return;
    }
    if ((algoVersion_ > PIN_ALGO_VERSION_V1) && (mode_ == GET_DATA_MODE_ALL_IN_ONE_PIN_ENROLL) &&
        (!GetSha256(dataIn, dataOut))) {
        IAM_LOGE("get sha256 fail");
        if (!dataOut.empty()) {
            (void)memset_s(dataOut.data(), dataOut.size(), 0, dataOut.size());
        }
        dataOut.clear();
    }
}

void InputerDataImpl::OnSetData(int32_t authSubType, std::vector<uint8_t> data)
{
    IAM_LOGI("start userId:%{public}d, data size:%{public}zu, algo version:%{public}u, complexityReg size:%{public}zu",
        userId_, data.size(), algoVersion_, complexityReg_.size());
    std::vector<uint8_t> setData;
    int32_t errorCode = UserAuth::GENERAL_ERROR;
    if (mode_ == GET_DATA_MODE_ALL_IN_ONE_RECOVERY_KEY_AUTH) {
        GetRecoveryKeyData(data, setData, errorCode);
    } else {
        GetPinData(authSubType, data, setData, errorCode);
    }
    OnSetDataInner(authSubType, setData, errorCode);
    if (!data.empty()) {
        (void)memset_s(data.data(), data.size(), 0, data.size());
    }
    if (!setData.empty()) {
        (void)memset_s(setData.data(), setData.size(), 0, setData.size());
    }
}

bool InputerDataImpl::GetSha256(const std::vector<uint8_t> &data, std::vector<uint8_t> &out)
{
    uint8_t sha256Result[SHA256_DIGEST_LENGTH] = {};
    if (SHA256(data.data(), data.size(), sha256Result) != sha256Result) {
        IAM_LOGE("get sha256 fail");
        (void)memset_s(sha256Result, SHA256_DIGEST_LENGTH, 0, SHA256_DIGEST_LENGTH);
        return false;
    }
    out.insert(out.end(), sha256Result, sha256Result + SHA256_DIGEST_LENGTH);
    (void)memset_s(sha256Result, SHA256_DIGEST_LENGTH, 0, SHA256_DIGEST_LENGTH);
    return true;
}

void InputerDataImpl::OnSetDataInner(int32_t authSubType, std::vector<uint8_t> &setData, int32_t errorCode)
{
    if (inputerSetData_ == nullptr) {
        IAM_LOGE("inputerSetData is nullptr");
        return;
    }
    inputerSetData_->OnSetData(authSubType, setData, errorCode);
}


int32_t InputerDataImpl::CheckPinComplexity(int32_t authSubType, const std::vector<uint8_t> &data)
{
    if (data.empty()) {
        IAM_LOGE("get empty data");
        return UserAuth::COMPLEXITY_CHECK_FAILED;
    }
    std::vector<uint8_t> input = data;
    input.emplace_back('\0');
    if (!CheckEdmPinComplexity(authSubType, input)) {
        IAM_LOGE("CheckEdmPinComplexity failed");
        (void)memset_s(input.data(), input.size(), 0, input.size());
        return UserAuth::COMPLEXITY_CHECK_FAILED;
    }
    if (!CheckSpecialPinComplexity(input)) {
        IAM_LOGE("CheckSpecialPinComplexity failed");
        (void)memset_s(input.data(), input.size(), 0, input.size());
        return UserAuth::COMPLEXITY_CHECK_FAILED;
    }
    if (data.size() < MIN_PIN_LENGTH) {
        IAM_LOGE("check data size failed");
        (void)memset_s(input.data(), input.size(), 0, input.size());
        return UserAuth::COMPLEXITY_CHECK_FAILED;
    }
    (void)memset_s(input.data(), input.size(), 0, input.size());

    return UserAuth::SUCCESS;
}

bool InputerDataImpl::CheckSpecialPinComplexity(std::vector<uint8_t> &input)
{
    if (mode_ != GET_DATA_MODE_ALL_IN_ONE_PIN_ENROLL && mode_ != GET_DATA_MODE_ALL_IN_ONE_PIN_AUTH) {
        return true;
    }
    if (complexityReg_.empty()) {
        IAM_LOGI("complexityReg is empty");
        return true;
    }
    const std::string key = "payment_security_level";
    int32_t isCheckPinComplexity = 0;
    if (!SettingsDataManager::GetIntValue(userId_, key, isCheckPinComplexity)) {
        IAM_LOGI("no exist isCheckPinComplexity");
        return true;
    }
    if (isCheckPinComplexity == 0) {
        IAM_LOGI("no need check special pin complexity");
        return true;
    }
    if (!CheckPinComplexityByReg(input, complexityReg_)) {
        IAM_LOGE("CheckPinComplexityByReg failed");
        return false;
    }
    return true;
}

bool InputerDataImpl::CheckEdmPinComplexity(int32_t authSubType, std::vector<uint8_t> &input)
{
    if (mode_ != GET_DATA_MODE_ALL_IN_ONE_PIN_ENROLL) {
        return true;
    }
#ifdef CUSTOMIZATION_ENTERPRISE_DEVICE_MANAGEMENT_ENABLE
    EDM::PasswordPolicy policy;
    int32_t ret = EDM::SecurityManagerProxy::GetSecurityManagerProxy()->GetPasswordPolicy(policy);
    if (ret != ERR_OK || policy.complexityReg.empty()) {
        IAM_LOGE("GetPasswordPolicy failed, use default policy");
        return true;
    }
    if (authSubType != UserAuth::PIN_MIXED) {
        IAM_LOGE("GetPasswordPolicy success, authSubType can only be PIN_MIXED");
        return false;
    }
    if (!CheckPinComplexityByReg(input, policy.complexityReg)) {
        IAM_LOGE("CheckPinComplexityByReg failed");
        return false;
    }
#else
    IAM_LOGI("This device not support edm, subType:%{public}d", authSubType);
#endif
    return true;
}

bool InputerDataImpl::CheckPinComplexityByReg(std::vector<uint8_t> &input, const std::string &complexityReg)
{
    try {
        std::regex regex(complexityReg);
        bool checkRet = std::regex_match(reinterpret_cast<char*>(input.data()), regex);
        if (!checkRet) {
            IAM_LOGE("PIN_MIXED does not pass complexity check");
            return false;
        }
    } catch (const std::regex_error &e) {
        IAM_LOGE("create regex failed");
        return false;
    }
    return true;
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
