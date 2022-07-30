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

#ifndef PIN_AUTH_MANAGER_H
#define PIN_AUTH_MANAGER_H

#include <cstdint>
#include <mutex>
#include <unordered_map>
#include <vector>

#include "iremote_object.h"
#include "refbase.h"
#include "singleton.h"

#include "inputer_get_data.h"
#include "i_inputer_data_impl.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
class PinAuthManager : public DelayedRefSingleton<PinAuthManager> {
    DECLARE_DELAYED_REF_SINGLETON(PinAuthManager);

public:
    bool RegisterInputer(uint32_t tokenId, sptr<InputerGetData> &inputer);
    void UnRegisterInputer(uint32_t tokenId);
    sptr<InputerGetData> getInputerLock(uint32_t tokenId);

private:
    std::unordered_map<uint32_t, sptr<InputerGetData>> pinAuthInputerMap_;
    std::mutex mutex_;
    class ResPinauthInputerDeathRecipient : public IRemoteObject::DeathRecipient, public NoCopyable {
    public:
        explicit ResPinauthInputerDeathRecipient(uint32_t tokenId);
        ~ResPinauthInputerDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override;

    private:
        uint32_t tokenId_;
    };
};
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS

#endif // PIN_AUTH_MANAGER_H
