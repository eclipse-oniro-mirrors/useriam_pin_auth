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

#include "inputer_set_data_proxy.h"

#include "iam_logger.h"

#define LOG_LABEL OHOS::UserIam::Common::LABEL_PIN_AUTH_SDK

namespace OHOS {
namespace UserIam {
namespace PinAuth {
void InputerSetDataProxy::OnSetData(int32_t authSubType, std::vector<uint8_t> data)
{
    IAM_LOGI("start");
    MessageParcel dataParcel;
    MessageParcel reply;

    if (!dataParcel.WriteInterfaceToken(InputerSetDataProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor fail");
    }

    if (!dataParcel.WriteInt32(authSubType)) {
        IAM_LOGE("write authSubType fail");
    }
    if (!dataParcel.WriteUInt8Vector(data)) {
        IAM_LOGE("write data fail");
    }

    bool ret = SendRequest(InputerSetDataInterfaceCode::ON_SET_DATA, dataParcel, reply);
    if (ret) {
        int32_t result = reply.ReadInt32();
        IAM_LOGI("result = %{public}d", result);
    }
}

bool InputerSetDataProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply)
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