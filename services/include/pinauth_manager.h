/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef PINAUTH_MANAGER_H
#define PINAUTH_MANAGER_H

#include <singleton.h>
#include <iremote_object.h>
#include <stdint.h>
#include <unordered_map>
#include <mutex>
#include <vector>

#include "pinauth_controller.h"
#include "refbase.h"
#include "iremote_inputer.h"

namespace OHOS {
namespace UserIAM {
namespace PinAuth {
class PinAuthManager : public DelayedRefSingleton<PinAuthManager> {
    DECLARE_DELAYED_REF_SINGLETON(PinAuthManager);
public:
    DISALLOW_COPY_AND_MOVE(PinAuthManager);
    void OnStart();
    bool RegisterInputer(uint64_t uid, sptr<IRemoteInputer> &inputer);
    void UnRegisterInputer(uint64_t uid);
    void Execute(uint64_t uid, uint64_t subType, uint64_t scheduleId,
                std::shared_ptr<PinAuth> pin, std::shared_ptr<AuthResPool::AuthAttributes> attributes);
    void SetMessenger(const sptr<AuthResPool::IExecutorMessenger> &messenger);
    void MapClear();
    int32_t Cancel(uint64_t scheduleId, std::shared_ptr<AuthResPool::AuthAttributes> consumerAttr);

private:
    std::unordered_map<uint64_t, sptr<IRemoteInputer>> pinAuthInputerMap_;
    std::unordered_map<uint64_t, sptr<PinAuthController>> pinAuthConMap_;
    sptr<AuthResPool::IExecutorMessenger> messenger_;
    std::mutex mutex_;

    sptr<PinAuthController> getPinAuthControllerLock(uint64_t scheduleId);
    void setPinAuthControllerLock(uint64_t scheduleId, sptr<PinAuthController> controller);
    sptr<IRemoteInputer> getInputerLock(uint64_t uid);

    // Death monitoring class
    class ResPinauthInputerDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        ResPinauthInputerDeathRecipient(uint64_t uid);
        ~ResPinauthInputerDeathRecipient() = default;
        void OnRemoteDied(const wptr<IRemoteObject>& remote) override;
    private:
        uint64_t uid_;
    };
};
} // namespace PinAuth
} // namespace UserIAM
} // namespace OHOS

#endif // PINAUTH_MANAGER_H
