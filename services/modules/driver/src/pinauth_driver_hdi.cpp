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

#include "pinauth_driver_hdi.h"

#include <vector>

#include "refbase.h"

#include "iam_logger.h"
#include "iam_ptr.h"

#include "pinauth_executor_hdi.h"
#include "v1_0/iexecutor.h"
#include "v1_0/ipin_auth_interface.h"

#define LOG_LABEL UserIam::Common::LABEL_PIN_AUTH_SA

namespace OHOS {
namespace UserIam {
namespace PinAuth {
void PinAuthDriverHdi::GetExecutorList(std::vector<std::shared_ptr<UserIam::UserAuth::IAuthExecutorHdi>> &executorList)
{
    IAM_LOGI("start");
    auto pinInterface = HDI::PinAuth::V1_0::IPinAuthInterface::Get();
    if (pinInterface == nullptr) {
        IAM_LOGE("IPinAuthInterface is null");
        return;
    }

    std::vector<sptr<HDI::PinAuth::V1_0::IExecutor>> iExecutorList;
    pinInterface->GetExecutorList(iExecutorList);
    for (const auto &iExecutor : iExecutorList) {
        auto executor = UserIAM::Common::MakeShared<PinAuthExecutorHdi>(iExecutor);
        if (executor == nullptr) {
            IAM_LOGE("make share failed");
            continue;
        }
        executorList.push_back(executor);
    }
}
} // PinAuth
} // UserIam
} // OHOS