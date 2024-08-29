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

#ifndef INPUTER_GET_DATA_PROXY_H
#define INPUTER_GET_DATA_PROXY_H

#include "iremote_proxy.h"
#include "message_parcel.h"
#include "nocopyable.h"

#include "inputer_get_data.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
class InputerGetDataProxy : public IRemoteProxy<InputerGetData>, public NoCopyable {
public:
    explicit InputerGetDataProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<InputerGetData>(impl)
    {
    }
    ~InputerGetDataProxy() override = default;
    void OnGetData(const InputerGetDataParam &getDataParam) override;

private:
    static inline BrokerDelegator<InputerGetDataProxy> delegator_;
    bool SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply);
    bool WriteInputerGetDataParam(MessageParcel &data, const InputerGetDataParam &getDataParam);
};
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
#endif // INPUTER_GET_DATA_PROXY_H