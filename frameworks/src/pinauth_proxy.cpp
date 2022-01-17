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

#include "pinauth_proxy.h"
#include "pinauth_log_wrapper.h"

namespace OHOS {
namespace UserIAM {
namespace PinAuth {
PinAuthProxy::PinAuthProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<IRemotePinAuth>(object)
{
    PINAUTH_HILOGD(MODULE_FRAMEWORKS, "PinAuthProxy::PinAuthProxy");
}

PinAuthProxy::~PinAuthProxy()
{
    PINAUTH_HILOGD(MODULE_FRAMEWORKS, "PinAuthProxy::~PinAuthProxy");
}

bool PinAuthProxy::RegisterInputer(sptr<IRemoteInputer> inputer)
{
    MessageParcel data;
    MessageParcel reply;

    PINAUTH_HILOGD(MODULE_FRAMEWORKS, "PinAuthProxy::RegisterInputer");
    if (!data.WriteInterfaceToken(PinAuthProxy::GetDescriptor())) {
        PINAUTH_HILOGI(MODULE_FRAMEWORKS, "write descriptor failed!");
        return false;
    }

    if (!data.WriteRemoteObject(inputer->AsObject())) {
        return false;
    }

    bool ret = SendRequest(static_cast<int32_t>(IRemotePinAuth::REGISTER_INPUTER), data, reply, true);
    bool result = false;
    if (!ret) {
        PINAUTH_HILOGI(MODULE_FRAMEWORKS, "SendRequest is failed, error code: %d", ret);
    } else {
        result = reply.ReadBool();
        PINAUTH_HILOGI(MODULE_FRAMEWORKS, "SendRequest is OK");
    }
    return result;
}

void PinAuthProxy::UnRegisterInputer()
{
    MessageParcel data;
    MessageParcel reply;

    PINAUTH_HILOGD(MODULE_FRAMEWORKS, "PinAuthProxy::UnRegisterInputer");
    if (!data.WriteInterfaceToken(PinAuthProxy::GetDescriptor())) {
        PINAUTH_HILOGI(MODULE_FRAMEWORKS, "write descriptor failed!");
        return;
    }

    bool ret = SendRequest(static_cast<int32_t>(IRemotePinAuth::UNREGISTER_INPUTER), data, reply, false);
    if (!ret) {
        PINAUTH_HILOGI(MODULE_FRAMEWORKS, "UnRegisterInputer SendRequest failed!");
    }
}

bool PinAuthProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, bool isSync)
{
    PINAUTH_HILOGD(MODULE_FRAMEWORKS, "PinAuthProxy::SendRequest");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PINAUTH_HILOGD(MODULE_FRAMEWORKS, "failed to get remote.");
        return false;
    }
    MessageOption option(isSync ? MessageOption::TF_SYNC : MessageOption::TF_ASYNC);
    int32_t result = remote->SendRequest(code, data, reply, option);
    if (result != OHOS::NO_ERROR) {
        PINAUTH_HILOGD(MODULE_FRAMEWORKS, "failed to SendRequest.result = %{public}d", result);
        return false;
    }
    return true;
}
} // namespace PinAuth
} // namespace UserIAM
} // namespace OHOS