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

#include "pin_auth_proxy.h"

#include "ipc_types.h"

#include "iam_logger.h"
#include "iremote_inputer.h"
#include "iremote_pinauth.h"

#define LOG_LABEL OHOS::UserIam::Common::LABEL_PIN_AUTH_SDK

namespace OHOS {
namespace UserIam {
namespace PinAuth {
PinAuthProxy::PinAuthProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<IRemotePinAuth>(object)
{
    IAM_LOGI("start");
}

bool PinAuthProxy::RegisterInputer(sptr<IRemoteInputer> inputer)
{
    IAM_LOGI("start");
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(PinAuthProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return false;
    }

    if (!data.WriteRemoteObject(inputer->AsObject())) {
        IAM_LOGE("failed to write inputer");
        return false;
    }

    bool ret = SendRequest(static_cast<uint32_t>(IRemotePinAuth::REGISTER_INPUTER), data, reply);
    if (!ret) {
        return false;
    }
    bool result = false;
    if (!reply.ReadBool(result)) {
        IAM_LOGE("failed to read result");
    }
    return result;
}

void PinAuthProxy::UnRegisterInputer()
{
    IAM_LOGI("start");
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(PinAuthProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return;
    }

    SendRequest(static_cast<uint32_t>(IRemotePinAuth::UNREGISTER_INPUTER), data, reply);
}

bool PinAuthProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("code = %{public}u", code);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        IAM_LOGE("failed to get remote");
        return false;
    }
    MessageOption option(MessageOption::TF_SYNC);
    int32_t result = remote->SendRequest(code, data, reply, option);
    if (result != OHOS::NO_ERROR) {
        IAM_LOGE("failed to send request, result = %{public}d", result);
        return false;
    }
    return true;
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS