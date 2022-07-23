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

#ifndef PINAUTH_MANAGER_H
#define PINAUTH_MANAGER_H

#include <cstdint>
#include <iremote_object.h>
#include <mutex>
#include <singleton.h>
#include <unordered_map>
#include <vector>
#include "iremote_inputer.h"
#include "i_inputer_data_impl.h"
#include "refbase.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
class PinAuthManager : public DelayedRefSingleton<PinAuthManager> {
    DECLARE_DELAYED_REF_SINGLETON(PinAuthManager);

public:
    bool RegisterInputer(uint32_t tokenId, sptr<IRemoteInputer> &inputer);
    void UnRegisterInputer(uint32_t tokenId);
    sptr<IRemoteInputer> getInputerLock(uint64_t uid);

private:
    std::unordered_map<uint32_t, sptr<IRemoteInputer>> pinAuthInputerMap_;
    std::mutex mutex_;
    class ResPinauthInputerDeathRecipient : public IRemoteObject::DeathRecipient, public NoCopyable {
    public:
        explicit ResPinauthInputerDeathRecipient(uint64_t uid);
        ~ResPinauthInputerDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override;

    private:
        uint64_t uid_;
    };
};
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS

#endif // PINAUTH_MANAGER_H
