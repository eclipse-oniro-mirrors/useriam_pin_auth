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
#include "i_inputer_proxy.h"

namespace OHOS {
namespace UserIAM {
namespace PinAuth {
void IInputerProxy::OnGetData(int32_t authSubType, std::vector<uint8_t> salt, sptr<IRemoteInputerData> inputerData)
{
    MessageParcel data;
    MessageParcel reply;
    PINAUTH_HILOGI(MODULE_SERVICE, "IInputerProxy::OnGetData enter");
    if (!data.WriteInterfaceToken(IInputerProxy::GetDescriptor())) {
        PINAUTH_HILOGE(MODULE_SERVICE, "WriteInterfaceToken failed!");
        return;
    }
    if (!data.WriteInt32(authSubType)) {
        PINAUTH_HILOGE(MODULE_SERVICE, "failed to WriteInt32(authSubType).");
    }

    if (!data.WriteUInt8Vector(salt)) {
        PINAUTH_HILOGI(MODULE_SERVICE, "failed to WriteUInt8Vector(salt).");
        return;
    }

    if (!data.WriteRemoteObject(inputerData->AsObject())) {
        PINAUTH_HILOGE(MODULE_SERVICE, "failed to WriteRemoteObject.");
        return;
    }
    bool ret = SendRequest(static_cast<uint32_t>(IRemoteInputer::ON_GET_DATA), data, reply);
    if (ret) {
        int32_t result = reply.ReadInt32();
        PINAUTH_HILOGI(MODULE_SERVICE, "result = %{public}d", result);
    }
}

bool IInputerProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    PINAUTH_HILOGI(MODULE_SERVICE, "IInputerProxy::SendRequest enter code:%{public}u", code);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PINAUTH_HILOGE(MODULE_SERVICE, "failed to get remote.");
        return false;
    }
    MessageOption option(MessageOption::TF_ASYNC);
    int32_t result = remote->SendRequest(code, data, reply, option);
    if (result != OHOS::NO_ERROR) {
        PINAUTH_HILOGE(MODULE_SERVICE, "failed to SendRequest.result = %{public}d", result);
        return false;
    }
    return true;
}
}  // namespace PinAuth
}  // namespace UserIAM
}  // namespace OHOS
