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

#ifndef IINPUTER_DATA_PROXY_H
#define IINPUTER_DATA_PROXY_H

#include "nocopyable.h"

#include "iremote_inputer.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace UserIAM {
namespace PinAuth {
class IInputerDataProxy : public IRemoteProxy<IRemoteInputerData> {
public:
    DISALLOW_COPY_AND_MOVE(IInputerDataProxy);
    explicit IInputerDataProxy(const sptr<IRemoteObject> &impl)
        : IRemoteProxy<IRemoteInputerData>(impl) {}
    ~IInputerDataProxy() override = default;
    void OnSetData(int32_t authSubType, std::vector<uint8_t> data) override;

private:
    bool SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply);
    static inline BrokerDelegator<IInputerDataProxy> delegator_;
};
}  // namespace PinAuth
}  // namespace UserIAM
}  // namespace OHOS

#endif  // IINPUTER_DATA_PROXY_H