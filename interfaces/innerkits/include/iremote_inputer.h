/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef IREMOTE_INPUTER_H
#define IREMOTE_INPUTER_H

#include "iremote_broker.h"
#include "iremote_object.h"
#include "iremote_inputer_data.h"

namespace OHOS {
namespace UserIAM {
namespace PinAuth {
class IRemoteInputer : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.PinAuth.IRemoteInputer");
    virtual void OnGetData(int32_t authSubType, std::vector<uint8_t> salt, sptr<IRemoteInputerData> inputerData) = 0;

    enum {
        ON_GET_DATA = 1
    };
};
} // namespace PinAuth
} // namespace UserIAM
} // namespace OHOS

#endif  // IREMOTE_INPUTER_H