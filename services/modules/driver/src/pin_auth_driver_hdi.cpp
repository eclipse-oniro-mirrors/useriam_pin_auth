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

#include "pin_auth_driver_hdi.h"

#include <vector>

#include "refbase.h"

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#include "load_mode_handler.h"
#include "pin_auth_all_in_one_hdi.h"
#include "pin_auth_collector_hdi.h"
#include "pin_auth_verifier_hdi.h"

#define LOG_TAG "PIN_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
PinAuthDriverHdi::PinAuthDriverHdi(const std::shared_ptr<PinAuthInterfaceAdapter> &pinAuthInterfaceAdapter)
    : pinAuthInterfaceAdapter_(pinAuthInterfaceAdapter)
{
}

void PinAuthDriverHdi::GetAllInOneExecutorList(std::vector<std::shared_ptr<UserAuth::IAuthExecutorHdi>> &executorList,
    std::vector<sptr<IAllInOneExecutor>> &iAllInOneExecutorList)
{
    IAM_LOGI("get all in one size %{public}zu", iAllInOneExecutorList.size());
    for (const auto &iAllInOne : iAllInOneExecutorList) {
        if (iAllInOne == nullptr) {
            IAM_LOGE("iAllInOne is nullptr");
            continue;
        }
        auto executor = Common::MakeShared<PinAuthAllInOneHdi>(iAllInOne);
        if (executor == nullptr) {
            IAM_LOGE("make share failed");
            continue;
        }
        executorList.push_back(executor);
    }
}

void PinAuthDriverHdi::GetCollectorExecutorList(std::vector<std::shared_ptr<UserAuth::IAuthExecutorHdi>> &executorList,
    std::vector<sptr<ICollector>> &iCollectorList)
{
    IAM_LOGI("get collector size %{public}zu", iCollectorList.size());
    for (const auto &iCollector : iCollectorList) {
        if (iCollector == nullptr) {
            IAM_LOGE("iCollector is nullptr");
            continue;
        }
        auto executor = Common::MakeShared<PinAuthCollectorHdi>(iCollector);
        if (executor == nullptr) {
            IAM_LOGE("make share failed");
            continue;
        }
        executorList.push_back(executor);
    }
}

void PinAuthDriverHdi::GetVerifierExecutorList(std::vector<std::shared_ptr<UserAuth::IAuthExecutorHdi>> &executorList,
    std::vector<sptr<IVerifier>> &iVerifierList)
{
    IAM_LOGI("get verifier size %{public}zu", iVerifierList.size());
    for (const auto &iVerifier : iVerifierList) {
        if (iVerifier == nullptr) {
            IAM_LOGE("iVerifier is nullptr");
            continue;
        }
        auto executor = Common::MakeShared<PinAuthVerifierHdi>(iVerifier);
        if (executor == nullptr) {
            IAM_LOGE("make share failed");
            continue;
        }
        executorList.push_back(executor);
    }
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

    std::vector<sptr<ICollector>> iCollectorList;
    std::vector<sptr<IVerifier>> iVerifierList;
    std::vector<sptr<IAllInOneExecutor>> iAllInOneExecutorList;
    auto ret = pinInterface->GetExecutorList(iAllInOneExecutorList, iVerifierList, iCollectorList);
    if (ret != HDF_SUCCESS) {
        IAM_LOGE("GetExecutorList fail");
        return;
    }
    GetAllInOneExecutorList(executorList, iAllInOneExecutorList);
    GetCollectorExecutorList(executorList, iCollectorList);
    GetVerifierExecutorList(executorList, iVerifierList);
    IAM_LOGI("get executor size %{public}zu", executorList.size());
}

void PinAuthDriverHdi::OnHdiDisconnect()
{
    IAM_LOGI("start");
}

void PinAuthDriverHdi::OnFrameworkDown()
{
    IAM_LOGI("start");
    LoadModeHandler::GetInstance().OnFrameworkDown();
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS