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

#ifndef PINAUTH_REGISTER_H
#define PINAUTH_REGISTER_H

#include <singleton.h>
#include <stdint.h>
#include <mutex>
#include "iremote_object.h"
#include "i_inputer.h"
#include "refbase.h"
#include "iremote_pinauth.h"

namespace OHOS {
namespace UserIAM {
namespace PinAuth {
class PinAuthRegister : public DelayedRefSingleton<PinAuthRegister> {
public:
    DECLARE_DELAYED_REF_SINGLETON(PinAuthRegister);

public:
    DISALLOW_COPY_AND_MOVE(PinAuthRegister);

public:
    bool RegisterInputer(std::shared_ptr<IInputer> inputer);
    void UnRegisterInputer();

private:
    class PinAuthDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        PinAuthDeathRecipient() = default;
        ~PinAuthDeathRecipient() = default;
        void OnRemoteDied(const wptr<IRemoteObject>& remote) override;

    private:
        DISALLOW_COPY_AND_MOVE(PinAuthDeathRecipient);
    };
    void ResetProxy(const wptr<IRemoteObject>& remote);
    std::mutex mutex_;
    sptr<IRemotePinAuth> GetProxy();
    sptr<IRemotePinAuth> proxy_ {nullptr};
    sptr<IRemoteObject::DeathRecipient> deathRecipient_ {nullptr};
};
} // namespace PinAuth
} // namespace UserIAM
} // namespace OHOS

#endif // PINAUTH_REGISTER_H
