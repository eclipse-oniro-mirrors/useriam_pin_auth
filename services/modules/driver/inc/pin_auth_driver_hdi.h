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

#ifndef PIN_AUTH_DRIVER_HDI
#define PIN_AUTH_DRIVER_HDI

#include <mutex>
#include <vector>

#include "nocopyable.h"

#include "iam_executor_iauth_driver_hdi.h"
#include "iremote_broker.h"
#include "iam_executor_iauth_executor_hdi.h"
#include "pin_auth_interface_adapter.h"
#include "pin_auth_hdi.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
class PinAuthDriverHdi : public UserAuth::IAuthDriverHdi, public NoCopyable {
public:
    explicit PinAuthDriverHdi(const std::shared_ptr<PinAuthInterfaceAdapter> &pinAuthInterfaceAdapter);
    ~PinAuthDriverHdi() override = default;
    void GetExecutorList(std::vector<std::shared_ptr<UserAuth::IAuthExecutorHdi>> &executorList) override;
    void OnHdiDisconnect() override;

private:
    void GetAllInOneExecutorList(std::vector<std::shared_ptr<UserAuth::IAuthExecutorHdi>> &executorList,
        std::vector<sptr<IAllInOneExecutor>> &iExecutorList);
    void GetCollectorExecutorList(std::vector<std::shared_ptr<UserAuth::IAuthExecutorHdi>> &executorList,
        std::vector<sptr<ICollector>> &iCollectorList);
    void GetVerifierExecutorList(std::vector<std::shared_ptr<UserAuth::IAuthExecutorHdi>> &executorList,
        std::vector<sptr<IVerifier>> &iVerifierList);

    const std::shared_ptr<PinAuthInterfaceAdapter> pinAuthInterfaceAdapter_;
};
} // PinAuth
} // UserIam
} // OHOS

#endif // PIN_AUTH_DRIVER_HDI