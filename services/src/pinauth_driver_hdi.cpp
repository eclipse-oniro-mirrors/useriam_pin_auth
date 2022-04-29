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
#include <v1_0/ipin_auth_interface.h>
#include "pinauth_log_wrapper.h"
#include "iauth_executor_hdi.h"
#include "pinauth_executor_hdi.h"

namespace OHOS {
namespace UserIAM {
namespace PinAuth {
    void PinAuthDriverHDI::GetExecutorList(std::vector<std::shared_ptr<UserAuth::IAuthExecutorHDI>>& executorList)
    {
        auto pinInterface = HDI::Pinauth::V1_0::IPinAuthInterface::Get();
        if (pinInterface == nullptr) {
            PINAUTH_HILOGI(MODULE_SERVICE, "IPinAuthInterface is null");
            return;
        }

        std::vector<sptr<HDI::Pinauth::V1_0::IExecutor>> iExecutorList;
        pinInterface->GetExecutorList(iExecutorList);
        for (auto iExecutor : iExecutorList) {
            auto executor = std::make_shared<PinAuthExecutorHDI>(iExecutor);
            executorList.push_back(executor);
        }
    }
} // PinAuth
} // UserIAM
} // OHOS