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

#include "pinauth_proxy.h"

#include "ipc_types.h"
#include "iremote_object.h"
#include "message_option.h"
#include "message_parcel.h"

#include "iam_logger.h"
#include "iremote_inputer.h"
#include "iremote_pinauth.h"

#define LOG_LABEL OHOS::UserIAM::Common::LABEL_PIN_AUTH_SDK

namespace OHOS {
namespace UserIAM {
namespace PinAuth {
PinAuthProxy::PinAuthProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<IRemotePinAuth>(object)
{
    IAM_LOGI("start");
}

PinAuthProxy::~PinAuthProxy()
{
    IAM_LOGI(" start");
}

bool PinAuthProxy::RegisterInputer(sptr<IRemoteInputer> inputer)
{
    MessageParcel data;
    MessageParcel reply;

    IAM_LOGI("start");
    if (!data.WriteInterfaceToken(PinAuthProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor fail");
        return false;
    }

    if (!data.WriteRemoteObject(inputer->AsObject())) {
        IAM_LOGE("write inputer fail");
        return false;
    }

    bool ret = SendRequest(static_cast<int32_t>(IRemotePinAuth::REGISTER_INPUTER), data, reply, true);
    bool result = false;
    if (!ret) {
        IAM_LOGE("send request fail, error code = %d", ret);
    } else {
        result = reply.ReadBool();
        IAM_LOGI("send request success");
    }
    return result;
}

void PinAuthProxy::UnRegisterInputer()
{
    MessageParcel data;
    MessageParcel reply;

    IAM_LOGI("start");
    if (!data.WriteInterfaceToken(PinAuthProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor fail");
        return;
    }

    bool ret = SendRequest(static_cast<int32_t>(IRemotePinAuth::UNREGISTER_INPUTER), data, reply, false);
    if (!ret) {
        IAM_LOGE("send request fail");
    }
}

bool PinAuthProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, bool isSync)
{
    IAM_LOGI("start");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        IAM_LOGE("remote is nullptr");
        return false;
    }
    MessageOption option(isSync ? MessageOption::TF_SYNC : MessageOption::TF_ASYNC);
    int32_t result = remote->SendRequest(code, data, reply, option);
    if (result != OHOS::NO_ERROR) {
        IAM_LOGE("send request fail, result = %{public}d", result);
        return false;
    }
    return true;
}
} // namespace PinAuth
} // namespace UserIAM
} // namespace OHOS