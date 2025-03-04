/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "load_mode_handler_dynamic.h"

#include "driver_load_manager.h"
#include "iam_logger.h"
#include "system_param_manager.h"

#define LOG_TAG "PIN_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
LoadModeHandlerDynamic::LoadModeHandlerDynamic()
{
    IAM_LOGI("sa load mode is dynamic");
}

void LoadModeHandlerDynamic::StartSubscribe()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (isSubscribed_) {
        return;
    }

    DriverLoadManager::GetInstance().StartSubscribe();

    isSubscribed_ = true;
}

void LoadModeHandlerDynamic::OnFrameworkDown()
{
    IAM_LOGI("fwk down");
    SystemParamManager::GetInstance().SetParam(FWK_READY_KEY, FALSE_STR);
    SystemParamManager::GetInstance().SetParam(IS_PIN_FUNCTION_READY_KEY, FALSE_STR);
    bool isPinEnrolled = SystemParamManager::GetInstance().GetParam(IS_PIN_ENROLLED_KEY, FALSE_STR) == TRUE_STR;
    if (isPinEnrolled) {
        IAM_LOGI("pin auth service down, pin enrolled, wait fwk ready");
    } else {
        bool isStopSa = SystemParamManager::GetInstance().GetParam(STOP_SA_KEY, FALSE_STR) == TRUE_STR;
        if (isStopSa) {
            IAM_LOGI("Sa is stopping, not need stop sa");
        } else {
            IAM_LOGI("pin auth service down, pin not enrolled, stop sa");
            SystemParamManager::GetInstance().SetParamTwice(STOP_SA_KEY, FALSE_STR, TRUE_STR);
        }
    }
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS