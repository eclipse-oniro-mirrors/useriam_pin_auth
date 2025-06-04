/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef INPUTER_SET_DATA_H
#define INPUTER_SET_DATA_H

#include <vector>

#include "iremote_broker.h"
#include "iremote_object.h"

#include "inputer_set_data_ipc_interface_code.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
class InputerSetData : public IRemoteBroker {
public:
    /*
     * the inputer is used to set the data.
     *
     * param authSubType auth subType.
     * param data pin data.
     * param pinLength pin data length.
     * param errorCode error code.
     */
    virtual void OnSetData(int32_t authSubType, std::vector<uint8_t> data, uint32_t pinLength, int32_t errorCode) = 0;

    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.PinAuth.InputerSetData");
};
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
#endif // INPUTER_SET_DATA_H