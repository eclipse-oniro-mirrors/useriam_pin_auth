/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef MOCK_PIN_AUTH_INTERFACE_H
#define MOCK_PIN_AUTH_INTERFACE_H

#include "gmock/gmock.h"
#include "iremote_object.h"
#include "inputer_get_data.h"
#include "pin_auth_hdi.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
using namespace OHOS;
using namespace OHOS::HDI;

class MockPinAuthInterface : public IRemoteObject {
public:
    MockPinAuthInterface() : IRemoteObject(u"")
    {
    }
    virtual ~MockPinAuthInterface() = default;
    MOCK_METHOD0(AsObject, sptr<IRemoteObject>());
    MOCK_METHOD1(RegisterInputer, bool(sptr<InputerGetData> &callback));
    MOCK_METHOD0(GetObjectRefCount, int32_t());
    MOCK_METHOD4(SendRequest, int(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option));
    MOCK_METHOD1(AddDeathRecipient, bool(const sptr<DeathRecipient> &recipient));
    MOCK_METHOD1(RemoveDeathRecipient, bool(const sptr<DeathRecipient> &recipient));
    MOCK_METHOD2(Dump, int(int fd, const std::vector<std::u16string> &args));
};
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS

#endif // MOCK_PIN_AUTH_INTERFACE_H