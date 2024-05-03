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

#ifndef PIN_AUTH_EXECUTOR_CALLBACK_HDI
#define PIN_AUTH_EXECUTOR_CALLBACK_HDI

#include <cstdint>
#include <vector>

#include "nocopyable.h"

#include "iam_executor_iexecute_callback.h"
#include "pin_auth_hdi.h"
#include "pin_auth_manager.h"
#include "pin_auth_all_in_one_hdi.h"
#include "pin_auth_collector_hdi.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
class PinAuthExecutorCallbackHdi : public IExecutorCallback, public NoCopyable {
public:
    PinAuthExecutorCallbackHdi(std::shared_ptr<UserAuth::IExecuteCallback> frameworkCallback,
        std::shared_ptr<PinAuthAllInOneHdi> pinAuthAllInOneHdi, uint32_t tokenId, GetDataMode mode,
        uint64_t scheduleId);
    PinAuthExecutorCallbackHdi(std::shared_ptr<UserAuth::IExecuteCallback> frameworkCallback,
        std::shared_ptr<PinAuthCollectorHdi> pinAuthCollectorHdi, uint32_t tokenId, GetDataMode mode,
        uint64_t scheduleId);
    PinAuthExecutorCallbackHdi(std::shared_ptr<UserAuth::IExecuteCallback> frameworkCallback,
        uint32_t tokenId, GetDataMode mode, uint64_t scheduleId);
    ~PinAuthExecutorCallbackHdi() override = default;
    int32_t OnResult(int32_t code, const std::vector<uint8_t> &extraInfo) override;
    int32_t OnGetData(const std::vector<uint8_t>& algoParameter, uint64_t authSubType, uint32_t algoVersion,
         const std::vector<uint8_t>& challenge) override;
    int32_t OnTip(int32_t tip, const std::vector<uint8_t>& extraInfo) override;
    int32_t OnMessage(int32_t destRole, const std::vector<uint8_t>& msg) override;

private:
    void DoVibrator();
    std::shared_ptr<UserAuth::IExecuteCallback> frameworkCallback_;
    std::shared_ptr<PinAuthAllInOneHdi> pinAuthAllInOneHdi_;
    std::shared_ptr<PinAuthCollectorHdi> pinAuthCollectorHdi_;
    UserAuth::ResultCode ConvertResultCode(const int32_t in);
    uint32_t tokenId_;
    GetDataMode mode_;
    uint64_t scheduleId_;
};
} // PinAuth
} // UserIam
} // OHOS

#endif // PIN_AUTH_EXECUTOR_CALLBACK_HDI