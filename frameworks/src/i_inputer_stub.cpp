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

#include "i_inputer_stub.h"

#include "inputer_data_impl.h"
#include "iremote_inputer.h"
#include "iremote_stub.h"
#include "pinauth_defines.h"
#include "pinauth_log_wrapper.h"

namespace OHOS {
namespace UserIAM {
namespace PinAuth {
IInputerStub::IInputerStub(std::shared_ptr<IInputer> inputer) : inputer_(inputer)
{
}
IInputerStub::~IInputerStub() = default;

void IInputerStub::HandlerOnGetData(MessageParcel &data, MessageParcel &reply)
{
    int32_t authSubType = data.ReadInt32();
    std::vector<uint8_t> salt;
    data.ReadUInt8Vector(&salt);
    sptr<IRemoteObject> remote = data.ReadRemoteObject();
    PINAUTH_HILOGI(MODULE_SERVICE, "IInputerStub::HandlerOnGetData start %{public}d", authSubType);
    if (remote == nullptr) {
        PINAUTH_HILOGI(MODULE_SERVICE, "IInputerStub::HandlerOnGetData remote == nullptr");
        return;
    }
    sptr<IRemoteInputerData> inputerData = iface_cast<IRemoteInputerData>(remote);
    if (inputerData == nullptr) {
        PINAUTH_HILOGI(MODULE_SERVICE, "IInputerStub::HandlerOnGetData inputerData == nullptr");
        return;
    }
    OnGetData(authSubType, salt, inputerData.GetRefPtr());
}

void IInputerStub::OnGetData(int32_t authSubType, std::vector<uint8_t> salt, sptr<IRemoteInputerData> inputerData)
{
    PINAUTH_HILOGI(MODULE_SERVICE, "IInputerStub::OnGetData enter");
    if (inputerData == nullptr) {
        PINAUTH_HILOGI(MODULE_SERVICE, "IInputerStub::OnGetData inputerData == nullptr");
        return;
    }
    std::shared_ptr<IInputerData> sharedInputerData = std::make_shared<InputerDataImpl>(salt, inputerData);
    inputer_->OnGetData(authSubType, sharedInputerData);
}

int32_t IInputerStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    PINAUTH_HILOGI(MODULE_SERVICE, "IInputerStub::OnRemoteRequest code:%{public}d,%{public}u", code, code);
    std::u16string descripter = IInputerStub::GetDescriptor();
    std::u16string remoteDescripter = data.ReadInterfaceToken();
    PINAUTH_HILOGI(MODULE_SERVICE, "IInputerStub::OnRemoteRequest descripter:%s, remoteDescripter:%s",
        (char *)(descripter.c_str()), (char *)(remoteDescripter.c_str()));
    if (descripter != remoteDescripter) {
        PINAUTH_HILOGI(MODULE_SERVICE, "IInputerStub::OnRemoteRequest descripter != remoteDescripter");
        return FAIL;
    }

    switch (code) {
        case static_cast<int32_t>(IRemoteInputer::ON_GET_DATA):
            HandlerOnGetData(data, reply);
            return SUCCESS;
        default:
            PINAUTH_HILOGI(MODULE_SERVICE, "IInputerStub::OnRemoteRequest default");
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return SUCCESS;
}
} // namespace PinAuth
} // namespace UserIAM
} // namespace OHOS
