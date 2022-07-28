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

#ifndef PINAUTH_IINPUTER_IMPL_H
#define PINAUTH_IINPUTER_IMPL_H

#include "inputer_impl.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#include "inputer_data_impl.h"

#define LOG_LABEL OHOS::UserIam::Common::LABEL_PIN_AUTH_SDK

namespace OHOS {
namespace UserIam {
namespace PinAuth {
InputerImpl::InputerImpl(const std::shared_ptr<IInputer> &inputer) : inputer_(inputer) {}
InputerImpl::~InputerImpl() = default;

void InputerImpl::OnGetData(int32_t authSubType, std::vector<uint8_t> salt, sptr<IRemoteInputerData> inputerData)
{
    IAM_LOGI("start");
    if (inputerData == nullptr) {
        IAM_LOGE("inputerData is nullptr");
        return;
    }
    
    std::shared_ptr<IInputerData> sharedInputerData = Common::MakeShared<InputerDataImpl>(salt, inputerData);
    if (sharedInputerData == nullptr) {
        IAM_LOGE("sharedInputerData is nullptr");
        return;
    }
    inputer_->OnGetData(authSubType, sharedInputerData);
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS

#endif // PINAUTH_IINPUTER_H
