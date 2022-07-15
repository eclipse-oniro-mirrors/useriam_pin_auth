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

#ifndef IREMOTE_INPUTER_DATA_H
#define IREMOTE_INPUTER_DATA_H

#include <vector>
#include "iremote_broker.h"
#include "iremote_object.h"

namespace OHOS {
namespace UserIAM {
namespace PinAuth {
class IRemoteInputerData : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.PinAuth.IRemoteInputerData");

    /*
     * the inputer is used to set the data.
     *
     * param authSubType auth subType.
     * param data pin data.
     */
    virtual void OnSetData(int32_t authSubType, std::vector<uint8_t> data) = 0;

    enum {
        ON_SET_DATA = 1
    };
};
} // namespace PinAuth
} // namespace UserIAM
} // namespace OHOS

#endif  // IREMOTE_INPUTER_DATA_H