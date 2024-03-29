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

#include "i_inputer_data_impl.h"

#include "iam_logger.h"
#include "pin_auth_executor_callback_manager.h"
#include "pin_auth_executor_hdi.h"

#define LOG_TAG "PIN_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
using namespace OHOS::UserIam::UserAuth;
IInputerDataImpl::IInputerDataImpl(uint64_t scheduleId, std::shared_ptr<PinAuthExecutorHdi> hdi)
    : scheduleId_(scheduleId), hdi_(hdi) {}
IInputerDataImpl::~IInputerDataImpl() {}

void IInputerDataImpl::OnSetData(int32_t authSubType, std::vector<uint8_t> data, int32_t errorCode)
{
    IAM_LOGI("start");
    std::lock_guard<std::mutex> guard(mutex_);
    if (hdi_ == nullptr) {
        IAM_LOGE("pin auth executor hdi is nullptr");
        return;
    }
    auto callback = PinAuthExecutorCallbackManager::GetInstance().GetCallbackLock(scheduleId_);
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return;
    }
    callback->SetErrorCode(errorCode);
    PinAuthExecutorCallbackManager::GetInstance().RemoveCallback(scheduleId_);
    if (hdi_->OnSetData(scheduleId_, authSubType, data) != SUCCESS) {
        IAM_LOGE("event has canceled");
        return;
    }

    IAM_LOGI("end");
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
