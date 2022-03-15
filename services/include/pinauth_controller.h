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

#ifndef PINAUTH_CONTROLLER_H
#define PINAUTH_CONTROLLER_H

#include <cstdint>
#include <mutex>
#include <vector>
#include "auth_attributes.h"
#include "i_inputer_data_stub.h"
#include "iexecutor_messenger.h"
#include "if_system_ability_manager.h"
#include "nocopyable.h"
#include "pin_auth.h"
#include "pinauth_stub.h"

namespace OHOS {
namespace UserIAM {
namespace PinAuth {
const uint32_t DEVICE_UUID_LENGTH = 65;
const uint32_t SHA256_LENGTH = 256;
const uint32_t RANDOM_LENGTH = 32;
void NewSalt(std::vector<uint8_t> &saltV);

class PinAuthController : public IInputerDataStub {
public:
    DISALLOW_COPY_AND_MOVE(PinAuthController);
    PinAuthController();
    ~PinAuthController() override;
    bool OnStart(std::vector<uint8_t> &salt);
    void OnSetData(int32_t authSubType, std::vector<uint8_t> data) override;
    void SaveParam(uint64_t scheduleId, std::shared_ptr<PinAuth> pin,
                   std::shared_ptr<AuthResPool::AuthAttributes> attributes);
    void SetMessenger(const sptr<AuthResPool::IExecutorMessenger> &messenger);
    void Cancel();

private:
    std::shared_ptr<PinAuth> pin_; // CA interface
    uint32_t command_;
    uint64_t templateId_;
    uint64_t scheduleId_;
    std::vector<uint8_t> salt_;
    std::shared_ptr<AuthResPool::AuthAttributes> attributes_;
    sptr<AuthResPool::IExecutorMessenger> messenger_;
    std::mutex mutex_;
    bool canceled = false;
};
} // namespace PinAuth
} // namespace UserIAM
} // namespace OHOS

#endif // PINAUTH_CONTROLLER_H
