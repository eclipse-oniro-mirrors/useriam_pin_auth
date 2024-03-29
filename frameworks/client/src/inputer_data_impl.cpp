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

#include "inputer_data_impl.h"

#include <cstddef>
#include <regex>
#include <vector>

#include <openssl/sha.h>

#include "iam_logger.h"
#include "iam_ptr.h"
#include "scrypt.h"
#include "security_manager_proxy.h"

#define LOG_TAG "PIN_AUTH_SDK"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
namespace {
constexpr uint32_t MIN_PIN_LENGTH = 6;
}

InputerDataImpl::InputerDataImpl(const std::vector<uint8_t> &algoParameter, const sptr<InputerSetData> &inputerSetData,
    uint32_t algoVersion, bool isEnroll) : algoParameter_(algoParameter),
    inputerSetData_(inputerSetData), algoVersion_(algoVersion), isEnroll_(isEnroll)
{
}

void InputerDataImpl::OnSetData(int32_t authSubType, std::vector<uint8_t> data)
{
    IAM_LOGI("start and data size:%{public}zu algo version:%{public}u", data.size(), algoVersion_);
    std::vector<uint8_t> setData;
    int32_t errorCode = {UserAuth::SUCCESS};
    if (isEnroll_) {
        errorCode = CheckPinComplexity(authSubType, data);
        if (errorCode != UserAuth::SUCCESS) {
            IAM_LOGE("CheckPinComplexity failed");
            return OnSetDataInner(authSubType, setData, errorCode);
        }
    } else {
        if (data.size() == 0) {
            IAM_LOGE("auth pin data size is 0");
            return OnSetDataInner(authSubType, setData, errorCode);
        }
    }

    auto scryptPointer = Common::MakeUnique<Scrypt>(algoParameter_);
    if (scryptPointer == nullptr) {
        IAM_LOGE("scryptPointer is nullptr");
        return OnSetDataInner(authSubType, setData, errorCode);
    }
    setData = scryptPointer->GetScrypt(data, algoVersion_);
    if (setData.empty()) {
        IAM_LOGE("get scrypt fail");
        return OnSetDataInner(authSubType, setData, errorCode);
    }
    if ((algoVersion_ > ALGO_VERSION_V1) && isEnroll_ && (!GetSha256(data, setData))) {
        IAM_LOGE("get sha256 fail");
        setData.clear();
    }
    return OnSetDataInner(authSubType, setData, errorCode);
}

bool InputerDataImpl::GetSha256(std::vector<uint8_t> &data, std::vector<uint8_t> &out)
{
    uint8_t sha256Result[SHA256_DIGEST_LENGTH] = {};
    if (SHA256(data.data(), data.size(), sha256Result) != sha256Result) {
        IAM_LOGE("get sha256 fail");
        return false;
    }
    out.insert(out.end(), sha256Result, sha256Result + SHA256_DIGEST_LENGTH);
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

int32_t InputerDataImpl::CheckPinComplexity(int32_t authSubType, std::vector<uint8_t> data)
{
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
    std::regex regex(policy.complexityReg);
    bool checkRet = std::regex_match(reinterpret_cast<char*>(data.data()), regex);
    if (!checkRet) {
        IAM_LOGE("PIN_MIXED does not pass complexity check");
        return UserAuth::COMPLEXITY_CHECK_FAILED;
    }

    return UserAuth::SUCCESS;
}

} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
