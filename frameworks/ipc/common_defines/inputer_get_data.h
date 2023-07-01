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

#ifndef INPUTER_GET_DATA_H
#define INPUTER_GET_DATA_H

#include "iremote_broker.h"
#include "iremote_object.h"

#include "inputer_set_data.h"
#include "inputer_get_data_ipc_interface_code.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
class InputerGetData : public IRemoteBroker {
public:
    /*
     * request inputer to get data.
     *
     * param authSubType auth subType.
     * param salt desensitization for pin data.
     * param inputerData callback for getting data.
     */
    virtual void OnGetData(int32_t authSubType, const std::vector<uint8_t> &salt,
        const sptr<InputerSetData> &inputerSetData) = 0;

    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.PinAuth.InputerGetData");
};
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
#endif // INPUTER_GET_DATA_H