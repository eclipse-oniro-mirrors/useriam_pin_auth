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

#include "inputer_get_data_service.h"

#include "iam_logger.h"
#include "iam_ptr.h"
#include "inputer_data_impl.h"

#define LOG_TAG "PIN_AUTH_SDK"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
InputerGetDataService::InputerGetDataService(const std::shared_ptr<IInputer> &inputer) : inputer_(inputer)
{
}

void InputerGetDataService::OnGetData(const InputerGetDataParam &getDataParam)
{
    IAM_LOGI("start");
    if (getDataParam.inputerSetData == nullptr) {
        IAM_LOGE("inputerSetData is nullptr");
        return;
    }

    std::shared_ptr<IInputerData> sharedInputerData = Common::MakeShared<InputerDataImpl>(getDataParam);
    if (sharedInputerData == nullptr) {
        IAM_LOGE("sharedInputerData is nullptr");
        return;
    }
    if (inputer_ == nullptr) {
        IAM_LOGE("inputer is nullptr");
        return;
    }
    inputer_->OnGetData(getDataParam.authSubType, getDataParam.challenge, sharedInputerData);
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
