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

#include "iremote_inputer.h"
#include "iremote_proxy.h"
#include "pinauth_log_wrapper.h"
#include "i_inputer_data_proxy.h"

namespace OHOS {
namespace UserIAM {
namespace PinAuth {
void IInputerDataProxy::OnSetData(int32_t authSubType, std::vector<uint8_t> data)
{
    PINAUTH_HILOGD(MODULE_FRAMEWORKS, "IInputerDataProxy::OnSetData");
    MessageParcel dataParcel;
    MessageParcel reply;

    if (!dataParcel.WriteInterfaceToken(IInputerDataProxy::GetDescriptor())) {
        PINAUTH_HILOGE(MODULE_FRAMEWORKS, "write descriptor failed!");
    }

    if (!dataParcel.WriteInt64(authSubType)) {
        PINAUTH_HILOGE(MODULE_FRAMEWORKS, "fail to wirte parcellable for WriteInt64");
    }
    if (!dataParcel.WriteUInt8Vector(data)) {
        PINAUTH_HILOGE(MODULE_FRAMEWORKS, "fail to wirte parcellable for WriteUInt8Vector");
    }

    bool ret = SendRequest(static_cast<uint32_t>(IRemoteInputerData::ON_SET_DATA), dataParcel, reply);
    if (ret) {
        int32_t result = reply.ReadInt32();
        PINAUTH_HILOGI(MODULE_FRAMEWORKS, "result = %{public}d", result);
    }
}

bool IInputerDataProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    PINAUTH_HILOGE(MODULE_FRAMEWORKS, "IInputerDataProxy::SendRequest");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PINAUTH_HILOGE(MODULE_FRAMEWORKS, "failed to get remote.");
        return false;
    }
    MessageOption option(MessageOption::TF_SYNC);
    int32_t result = remote->SendRequest(code, data, reply, option);
    if (result != OHOS::NO_ERROR) {
        PINAUTH_HILOGE(MODULE_FRAMEWORKS, "failed to SendRequest.result = %{public}d", result);
        return false;
    }
    return true;
}
} // namespace PinAuth
} // namespace UserIAM
} // namespace OHOS
