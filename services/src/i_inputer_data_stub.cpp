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

#include "i_inputer_data_stub.h"

#include "iremote_inputer.h"
#include "iremote_stub.h"
#include "pinauth_defines.h"
#include "pinauth_log_wrapper.h"

namespace OHOS {
namespace UserIAM {
namespace PinAuth {
void IInputerDataStub::HandlerOnSetData(MessageParcel &data, MessageParcel &reply)
{
    PINAUTH_HILOGI(MODULE_FRAMEWORKS, "IInputerDataStub::HandlerOnSetData enter");
    uint64_t subType = data.ReadUint64();
    std::vector<uint8_t> param;
    data.ReadUInt8Vector(&param);
    OnSetData(subType, param);
}

int32_t IInputerDataStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    PINAUTH_HILOGI(MODULE_FRAMEWORKS, "IInputerDataStub::OnRemoteRequest enter %{public}u", code);
    std::u16string descripter = IInputerDataStub::GetDescriptor();
    std::u16string remoteDescripter = data.ReadInterfaceToken();
    if (descripter != remoteDescripter) {
        PINAUTH_HILOGD(MODULE_FRAMEWORKS, "IInputerDataStub::OnRemoteRequest descripter != remoteDescripter");
        return FAIL;
    }
    switch (code) {
        case static_cast<int32_t>(IRemoteInputerData::ON_SET_DATA):
            HandlerOnSetData(data, reply);
            return SUCCESS;
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}
} // namespace PinAuth
} // namespace UserIAM
} // namespace OHOS
