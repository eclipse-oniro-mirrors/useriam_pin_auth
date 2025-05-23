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

#ifndef PIN_AUTH_ALL_IN_ONE_HDI_H
#define PIN_AUTH_ALL_IN_ONE_HDI_H

#include <cstdint>
#include <mutex>
#include <optional>
#include <vector>

#include "iam_executor_framework_types.h"
#include "iam_executor_iauth_executor_hdi.h"
#include "iam_executor_iexecute_callback.h"
#include "nocopyable.h"
#include "pin_auth_hdi.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
class PinAuthAllInOneHdi : public std::enable_shared_from_this<PinAuthAllInOneHdi>,
    public UserAuth::IAuthExecutorHdi, public NoCopyable {
public:
    explicit PinAuthAllInOneHdi(const sptr<IAllInOneExecutor> &allInOneProxy);
    ~PinAuthAllInOneHdi() override = default;

    UserAuth::ResultCode GetExecutorInfo(UserAuth::ExecutorInfo &info) override;
    UserAuth::ResultCode OnRegisterFinish(const std::vector<uint64_t> &templateIdList,
        const std::vector<uint8_t> &frameworkPublicKey, const std::vector<uint8_t> &extraInfo) override;
    UserAuth::ResultCode SendMessage(uint64_t scheduleId, int32_t srcRole, const std::vector<uint8_t> &msg) override;
    UserAuth::ResultCode Enroll(uint64_t scheduleId, const UserAuth::EnrollParam &param,
        const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) override;
    UserAuth::ResultCode Authenticate(uint64_t scheduleId, const UserAuth::AuthenticateParam &param,
        const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) override;
    UserAuth::ResultCode OnSetData(uint64_t scheduleId, uint64_t authSubType, const std::vector<uint8_t> &data,
        int32_t errorCode);
    UserAuth::ResultCode Delete(const std::vector<uint64_t> &templateIdList) override;
    UserAuth::ResultCode Cancel(uint64_t scheduleId) override;
    UserAuth::ResultCode GetProperty(const std::vector<uint64_t> &templateIdList,
        const std::vector<UserAuth::Attributes::AttributeKey> &keys, UserAuth::Property &property) override;
    UserAuth::ResultCode Abandon(uint64_t scheduleId, const UserAuth::DeleteParam &param,
            const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) override;
private:
    void MoveHdiProperty(Property &in, UserAuth::Property &out);
    UserAuth::ResultCode ConvertAttributeKeyToPropertyType(const UserAuth::Attributes::AttributeKey in, int32_t &out);
    UserAuth::ResultCode ConvertAttributeKeyVectorToPropertyType(
        const std::vector<UserAuth::Attributes::AttributeKey> inVector,
        std::vector<int32_t> &outVector);
    void SetAuthType(int32_t authType);
    std::optional<int32_t> GetAuthType();

    sptr<IAllInOneExecutor> allInOneProxy_ {nullptr};
    std::optional<int32_t> authType_ {std::nullopt};
    std::mutex mutex_;
};
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS

#endif // PIN_AUTH_ALL_IN_ONE_HDI_H