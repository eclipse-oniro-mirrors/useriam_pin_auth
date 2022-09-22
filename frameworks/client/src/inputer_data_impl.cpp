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
InputerDataImpl::InputerDataImpl(const std::vector<uint8_t> &salt, const sptr<InputerSetData> &inputerSetData)
    : salt_(salt), inputerSetData_(inputerSetData)
{
}

void InputerDataImpl::OnSetData(int32_t authSubType, std::vector<uint8_t> data)
{
    IAM_LOGI("start and data size is %{public}zu", data.size());
    auto scryptPointer = Common::MakeUnique<Scrypt>(salt_);
    if (scryptPointer == nullptr) {
        IAM_LOGE("scryptPointer is nullptr");
        return;
    }

    std::vector<uint8_t> scrypt = scryptPointer->GetScrypt(data);
    if (scrypt.empty()) {
        IAM_LOGE("get scrypt fail");
        return;
    }

    if (inputerSetData_ == nullptr) {
        IAM_LOGE("inputerSetData is nullptr");
        return;
    }
    inputerSetData_->OnSetData(authSubType, scrypt);
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
