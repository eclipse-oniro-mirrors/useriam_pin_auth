/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "pin_auth_executor_callback_manager.h"

#include "iam_logger.h"

#define LOG_TAG "PIN_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
PinAuthExecutorCallbackManager::PinAuthExecutorCallbackManager() = default;
PinAuthExecutorCallbackManager::~PinAuthExecutorCallbackManager() = default;
bool PinAuthExecutorCallbackManager::SetCallback(uint64_t scheduleId,
    const sptr<PinAuthExecutorCallbackHdi> &callback)
{
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return false;
    }

    std::lock_guard<std::mutex> guard(mutex_);
    IAM_LOGI("start");

    if (pinAuthExecutorCallbackMap_.find(scheduleId) != pinAuthExecutorCallbackMap_.end()) {
        IAM_LOGE("callback is already in map");
        return false;
    }

    pinAuthExecutorCallbackMap_.emplace(scheduleId, callback);
    return true;
}

void PinAuthExecutorCallbackManager::RemoveCallback(uint64_t scheduleId)
{
    std::lock_guard<std::mutex> guard(mutex_);
    IAM_LOGI("start");
    pinAuthExecutorCallbackMap_.erase(scheduleId);
}

sptr<PinAuthExecutorCallbackHdi> PinAuthExecutorCallbackManager::GetCallbackLock(uint64_t scheduleId)
{
    std::lock_guard<std::mutex> guard(mutex_);
    IAM_LOGI("start");

    auto callback = pinAuthExecutorCallbackMap_.find(scheduleId);
    if (callback != pinAuthExecutorCallbackMap_.end()) {
        IAM_LOGI("find callback");
        return callback->second;
    }
    IAM_LOGE("callback is not found");
    return nullptr;
}

} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
