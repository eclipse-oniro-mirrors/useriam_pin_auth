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

#ifndef PIN_AUTH_COLLECTOR_HDI_H
#define PIN_AUTH_COLLECTOR_HDI_H

#include <cstdint>
#include <map>
#include <vector>

#include "iam_executor_framework_types.h"
#include "iam_executor_iauth_executor_hdi.h"
#include "iam_executor_iexecute_callback.h"
#include "nocopyable.h"
#include "pin_auth_hdi.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
class PinAuthCollectorHdi : public std::enable_shared_from_this<PinAuthCollectorHdi>,
    public UserAuth::IAuthExecutorHdi, public NoCopyable {
public:
    explicit PinAuthCollectorHdi(const sptr<ICollector> &collectorProxy);
    ~PinAuthCollectorHdi() override = default;

    UserAuth::ResultCode GetExecutorInfo(UserAuth::ExecutorInfo &info) override;
    UserAuth::ResultCode OnRegisterFinish(const std::vector<uint64_t> &templateIdList,
        const std::vector<uint8_t> &frameworkPublicKey, const std::vector<uint8_t> &extraInfo) override;
    UserAuth::ResultCode Cancel(uint64_t scheduleId) override;
    UserAuth::ResultCode SendMessage(uint64_t scheduleId, int32_t srcRole, const std::vector<uint8_t> &msg) override;
    UserAuth::ResultCode Collect(uint64_t scheduleId, const UserAuth::CollectParam &param,
        const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) override;
    UserAuth::ResultCode OnSetData(uint64_t scheduleId, uint64_t authSubType, const std::vector<uint8_t> &data,
        int32_t errorCode);

private:
    sptr<ICollector> collectorProxy_ { nullptr };
};
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS

#endif // PIN_AUTH_COLLECTOR_HDI_H