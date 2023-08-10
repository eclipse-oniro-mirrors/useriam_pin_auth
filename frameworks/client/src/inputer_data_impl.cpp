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
#include <vector>

#include "iam_logger.h"
#include "iam_ptr.h"
#include "scrypt.h"

#define LOG_LABEL OHOS::UserIam::Common::LABEL_PIN_AUTH_SDK

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
    IAM_LOGI("start and data size is %{public}zu", data.size());
    std::vector<uint8_t> scrypt;
    if (isEnroll_) {
        if (data.size() < MIN_PIN_LENGTH) {
            IAM_LOGE("enroll pin data size is less than min pin data length");
            return OnSetDataInner(authSubType, scrypt);
        }
    } else {
        if (data.size() == 0) {
            IAM_LOGE("auth pin data size is 0");
            return OnSetDataInner(authSubType, scrypt);
        }
    }

    auto scryptPointer = Common::MakeUnique<Scrypt>(algoParameter_);
    if (scryptPointer == nullptr) {
        IAM_LOGE("scryptPointer is nullptr");
        return OnSetDataInner(authSubType, scrypt);
    }
    scrypt = scryptPointer->GetScrypt(data, algoVersion_);
    if (scrypt.empty()) {
        IAM_LOGE("get scrypt fail");
    }
    return OnSetDataInner(authSubType, scrypt);
}

void InputerDataImpl::OnSetDataInner(int32_t authSubType, std::vector<uint8_t> &scrypt)
{
    if (inputerSetData_ == nullptr) {
        IAM_LOGE("inputerSetData is nullptr");
        return;
    }
    inputerSetData_->OnSetData(authSubType, scrypt);
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
