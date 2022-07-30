/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License") = 0;
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

#ifndef PIN_AUTH_INTERFACE_H
#define PIN_AUTH_INTERFACE_H

#include "iremote_broker.h"
#include "iremote_object.h"

#include "inputer_get_data.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
class PinAuthInterface : public IRemoteBroker {
public:
    virtual bool RegisterInputer(const sptr<InputerGetData> &inputer) = 0;
    virtual void UnRegisterInputer() = 0;

    enum : uint32_t {
        REGISTER_INPUTER = 1,
        UNREGISTER_INPUTER = 2,
    };
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.PinAuth.PinAuthInterface");
};
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
#endif // PIN_AUTH_INTERFACE_H