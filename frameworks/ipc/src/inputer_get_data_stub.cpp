/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "inputer_get_data_stub.h"

#include "iam_logger.h"
#include "iam_common_defines.h"

#define LOG_TAG "PIN_AUTH_SDK"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
int32_t InputerGetDataStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    IAM_LOGI("cmd = %{public}u, flags = %{public}d", code, option.GetFlags());
    if (InputerGetDataStub::GetDescriptor() != data.ReadInterfaceToken()) {
        IAM_LOGE("descriptor is not matched");
        return UserAuth::GENERAL_ERROR;
    }
    switch (code) {
        case InputerGetDataInterfaceCode::ON_GET_DATA:
            OnGetDataStub(data, reply);
            return UserAuth::SUCCESS;
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

bool InputerGetDataStub::ReadInputerGetDataParam(MessageParcel &data, InputerGetDataParam &getDataParam)
{
    int32_t mode;
    if (!data.ReadInt32(mode)) {
        IAM_LOGE("failed to read mode");
        return false;
    }
    getDataParam.mode = static_cast<GetDataMode>(mode);
    if (!data.ReadInt32(getDataParam.authSubType)) {
        IAM_LOGE("failed to read authSubType");
        return false;
    }
    if (!data.ReadUint32(getDataParam.algoVersion)) {
        IAM_LOGE("failed to read algoVersion");
        return false;
    }
    if (!data.ReadUInt8Vector(&(getDataParam.algoParameter))) {
        IAM_LOGE("failed to read algoParameter");
        return false;
    }
    if (!data.ReadUInt8Vector(&(getDataParam.challenge))) {
        IAM_LOGE("failed to read challenge");
        return false;
    }
    if (!data.ReadInt32(getDataParam.userId)) {
        IAM_LOGE("failed to read userId");
        return false;
    }
    if (!data.ReadString(getDataParam.complexityReg)) {
        IAM_LOGE("failed to read complexityReg");
        return false;
    }
    if (!data.ReadInt32(getDataParam.authIntent)) {
        IAM_LOGE("failed to read authIntent");
        return false;
    }
    sptr<IRemoteObject> obj = data.ReadRemoteObject();
    if (obj == nullptr) {
        IAM_LOGE("failed to read remote object");
        return false;
    }
    getDataParam.inputerSetData = iface_cast<InputerSetData>(obj);
    if (getDataParam.inputerSetData == nullptr) {
        IAM_LOGE("inputerSetData is nullptr");
        return false;
    }
    return true;
}

void InputerGetDataStub::OnGetDataStub(MessageParcel &data, MessageParcel &reply)
{
    InputerGetDataParam getDataParam;
    if (!ReadInputerGetDataParam(data, getDataParam)) {
        IAM_LOGE("ReadInputerGetDataParam failed");
        return;
    }
    OnGetData(getDataParam);
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
