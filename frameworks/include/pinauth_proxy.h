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

#ifndef PINAUTH_PROXY_H
#define PINAUTH_PROXY_H

#include "iremote_pinauth.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace UserIAM {
namespace PinAuth {
class PinAuthProxy : public IRemoteProxy<IRemotePinAuth> {
public:
    explicit PinAuthProxy(const sptr<IRemoteObject> &object);
    virtual ~PinAuthProxy() override;
    virtual bool RegisterInputer(sptr<IRemoteInputer> inputer) override;
    virtual void UnRegisterInputer() override;

private:
    bool SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, bool isSync);

private:
    static inline BrokerDelegator<PinAuthProxy> delegator_;
};
}  // namespace PinAuth
}  // namespace UserIAM
}  // namespace OHOS

#endif  // PINAUTH_INNERKITS_INCLUDE_PIN_AUTH_PROXY_H