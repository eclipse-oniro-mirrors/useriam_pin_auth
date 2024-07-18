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

InputerDataImpl::InputerDataImpl(InputerGetDataParam param)
    : mode_(param.mode), algoVersion_(param.algoVersion), algoParameter_(param.algoParameter), inputerSetData_(param.inputerSetData),
      pinComplexity_(param.pinComplexity), userId_(param.userId)
{
}

void InputerDataImpl::GetPinData(
    int32_t authSubType, const std::vector<uint8_t> &dataIn, std::vector<uint8_t> &dataOut, int32_t &errorCode)
{
    errorCode = CheckPinComplexity(authSubType, dataIn);
    if (errorCode != UserAuth::SUCCESS) {
        IAM_LOGE("CheckPinComplexity failed");
        return;
    }

    if (mode_ == GET_DATA_MODE_ALL_IN_ONE_ENROLL && authSubType == UserAuth::PIN_PATTERN) {
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
    if ((algoVersion_ > ALGO_VERSION_V1) &&
        (mode_ == GET_DATA_MODE_ALL_IN_ONE_ENROLL) &&
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
    IAM_LOGI("start and data size:%{public}zu algo version:%{public}u", data.size(), algoVersion_);
    std::vector<uint8_t> setData;
    int32_t errorCode = UserAuth::GENERAL_ERROR;
    GetPinData(authSubType, data, setData, errorCode);
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
    //liuziwei
    const std::string key = "";
    std::string isCheckPinComplexity;
    SettingsDataManager::GetInstance().GetStringValue(userId_, key, isCheckPinComplexity);
    IAM_LOGE("liuziwei userId %{public}d", userId_);
    IAM_LOGE("liuziwei pinComplexity_ %{public}s", pinComplexity_.c_str());
    if (data.empty()) {
        IAM_LOGE("get empty data");
        return UserAuth::COMPLEXITY_CHECK_FAILED;
    }
    if (mode_ != GET_DATA_MODE_ALL_IN_ONE_ENROLL) {
        return UserAuth::SUCCESS;
    }
#ifdef CUSTOMIZATION_ENTERPRISE_DEVICE_MANAGEMENT_ENABLE
    EDM::PasswordPolicy policy;
    int32_t ret = EDM::SecurityManagerProxy::GetSecurityManagerProxy()->GetPasswordPolicy(policy);
    if (ret != ERR_OK || policy.complexityReg.empty()) {
        IAM_LOGE("GetPasswordPolicy failed, use default policy");
        return (data.size() >= MIN_PIN_LENGTH ? UserAuth::SUCCESS : UserAuth::COMPLEXITY_CHECK_FAILED);
    }
    if (authSubType != UserAuth::PIN_MIXED) {
        IAM_LOGE("GetPasswordPolicy success, authSubType can only be PIN_MIXED");
        return UserAuth::COMPLEXITY_CHECK_FAILED;
    }
    std::vector<uint8_t> input = data;
    input.emplace_back('\0');
    try {
        std::regex regex(policy.complexityReg);
        bool checkRet = std::regex_match(reinterpret_cast<char*>(input.data()), regex);
        if (!checkRet) {
            IAM_LOGE("PIN_MIXED does not pass complexity check");
            (void)memset_s(input.data(), input.size(), 0, input.size());
            return UserAuth::COMPLEXITY_CHECK_FAILED;
        }
    } catch (const std::regex_error &e) {
        IAM_LOGE("create regex failed");
        (void)memset_s(input.data(), input.size(), 0, input.size());
        return UserAuth::COMPLEXITY_CHECK_FAILED;
    }
    (void)memset_s(input.data(), input.size(), 0, input.size());
    return UserAuth::SUCCESS;
#else
    IAM_LOGI("This device not support edm, subType:%{public}d", authSubType);
    return (data.size() >= MIN_PIN_LENGTH ? UserAuth::SUCCESS : UserAuth::COMPLEXITY_CHECK_FAILED);
#endif
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
