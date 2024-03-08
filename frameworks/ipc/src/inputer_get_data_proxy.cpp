/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "inputer_get_data_proxy.h"

#include "iam_logger.h"

#define LOG_TAG "PIN_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
void InputerGetDataProxy::OnGetData(int32_t authSubType, const std::vector<uint8_t> &algoParameter,
    const sptr<InputerSetData> &inputerSetData, uint32_t algoVersion, bool isEnroll)
{
    IAM_LOGI("start");
    if (inputerSetData == nullptr) {
        IAM_LOGE("inputerSetData is nullptr");
        return;
    }
    
    MessageParcel data;
    MessageParcel reply;
    
    if (!data.WriteInterfaceToken(InputerGetDataProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor fail");
        return;
    }
    if (!data.WriteInt32(authSubType)) {
        IAM_LOGE("write authSubType fail");
        return;
    }

    if (!data.WriteUInt8Vector(algoParameter)) {
        IAM_LOGE("write algoParameter fail");
        return;
    }

    if (!data.WriteRemoteObject(inputerSetData->AsObject())) {
        IAM_LOGE("write inputerData fail");
        return;
    }
    if (!data.WriteUint32(algoVersion)) {
        IAM_LOGE("write algoVersion fail");
        return;
    }
    if (!data.WriteBool(isEnroll)) {
        IAM_LOGE("write isEnroll fail");
        return;
    }
    bool ret = SendRequest(InputerGetDataInterfaceCode::ON_GET_DATA, data, reply);
    if (ret) {
        int32_t result = reply.ReadInt32();
        IAM_LOGI("result = %{public}d", result);
    }
}

bool InputerGetDataProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply)
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
