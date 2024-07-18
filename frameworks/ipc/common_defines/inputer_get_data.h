/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
enum GetDataMode : int32_t {
    GET_DATA_MODE_NONE = 0,
    GET_DATA_MODE_ALL_IN_ONE_ENROLL = 1,
    GET_DATA_MODE_ALL_IN_ONE_AUTH = 2,
    GET_DATA_MODE_COLLECTOR = 3,
};

struct InputerGetDataParam {
    GetDataMode mode{GET_DATA_MODE_NONE};
    int32_t authSubType{0};
    uint32_t algoVersion{0};
    std::vector<uint8_t> algoParameter;
    std::vector<uint8_t> challenge;
    sptr<InputerSetData> inputerSetData;
    int32_t userId;
    std::string pinComplexity;
};

class InputerGetData : public IRemoteBroker {
public:
    /*
     * request inputer to get data.
     *
     * param getDataParam get data param.
     */
    virtual void OnGetData(const InputerGetDataParam &getDataParam) = 0;

    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.PinAuth.InputerGetData");
};
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
#endif // INPUTER_GET_DATA_H