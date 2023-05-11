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

#include "pin_auth_driver_hdi.h"

#include <vector>

#include "refbase.h"

#include "iam_logger.h"
#include "iam_ptr.h"

#include "pin_auth_executor_hdi.h"

#define LOG_LABEL UserIam::Common::LABEL_PIN_AUTH_SA

namespace OHOS {
namespace UserIam {
namespace PinAuth {
PinAuthDriverHdi::PinAuthDriverHdi(const std::shared_ptr<PinAuthInterfaceAdapter> &pinAuthInterfaceAdapter)
    : pinAuthInterfaceAdapter_(pinAuthInterfaceAdapter)
{
}

void PinAuthDriverHdi::GetExecutorList(std::vector<std::shared_ptr<UserAuth::IAuthExecutorHdi>> &executorList)
{
    IAM_LOGI("start");
    if (pinAuthInterfaceAdapter_ == nullptr) {
        IAM_LOGE("pinAuthInterfaceAdapter_ is null");
        return;
    }
    auto pinInterface = pinAuthInterfaceAdapter_->Get();
    if (pinInterface == nullptr) {
        IAM_LOGE("IPinAuthInterface is null");
        return;
    }

    std::vector<sptr<HDI::PinAuth::V1_1::IExecutor>> iExecutorList;
    auto ret = pinInterface->GetExecutorListV1_1(iExecutorList);
    if (ret != HDF_SUCCESS) {
        IAM_LOGE("GetExecutorList fail");
        return;
    }
    for (const auto &iExecutor : iExecutorList) {
        if (iExecutor == nullptr) {
            IAM_LOGE("iExecutor is nullptr");
            continue;
        }
        auto executor = Common::MakeShared<PinAuthExecutorHdi>(iExecutor);
        if (executor == nullptr) {
            IAM_LOGE("make share failed");
            continue;
        }
        executorList.push_back(executor);
    }
}

void PinAuthDriverHdi::OnHdiDisconnect()
{
    IAM_LOGI("start");
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS