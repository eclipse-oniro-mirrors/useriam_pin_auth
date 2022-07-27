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

#include "i_inputer_proxy.h"

#include "ipc_types.h"

#include "message_option.h"
#include "message_parcel.h"
#include "iremote_object.h"

#include "iam_logger.h"
#include "iremote_inputer.h"
#include "iremote_inputer_data.h"

#define LOG_LABEL UserIam::Common::LABEL_PIN_AUTH_SA

namespace OHOS {
namespace UserIam {
namespace PinAuth {
void IInputerProxy::OnGetData(int32_t authSubType, std::vector<uint8_t> salt, sptr<IRemoteInputerData> inputerData)
{
    MessageParcel data;
    MessageParcel reply;
    IAM_LOGI("start");
    if (!data.WriteInterfaceToken(IInputerProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor fail");
        return;
    }
    if (!data.WriteInt32(authSubType)) {
        IAM_LOGE("write authSubType fail");
        return;
    }

    if (!data.WriteUInt8Vector(salt)) {
        IAM_LOGE("write salt fail");
        return;
    }

    if (!data.WriteRemoteObject(inputerData->AsObject())) {
        IAM_LOGE("write inputerData fail");
        return;
    }
    bool ret = SendRequest(static_cast<uint32_t>(IRemoteInputer::ON_GET_DATA), data, reply);
    if (ret) {
        int32_t result = reply.ReadInt32();
        IAM_LOGI("result = %{public}d", result);
    }
}

bool IInputerProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("start, code = %{public}u", code);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        IAM_LOGE("remote is nullptr");
        return false;
    }
    MessageOption option(MessageOption::TF_ASYNC);
    int32_t result = remote->SendRequest(code, data, reply, option);
    if (result != OHOS::NO_ERROR) {
        IAM_LOGE("send request fail, result = %{public}d", result);
        return false;
    }
    return true;
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
