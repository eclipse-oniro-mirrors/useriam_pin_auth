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

#include "load_mode_handler_default.h"

#include "iam_logger.h"
#include "system_param_manager.h"

#define LOG_TAG "PIN_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
LoadModeHandlerDefault::LoadModeHandlerDefault()
{
    IAM_LOGI("sa load mode is default");
}

void LoadModeHandlerDefault::Init()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (isInit_) {
        return;
    }

    isInit_ = true;
}

void LoadModeHandlerDefault::OnFrameworkDown()
{
    IAM_LOGI("fwk down");
    SystemParamManager::GetInstance().SetParam(FWK_READY_KEY, FALSE_STR);
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS