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

#include "inputer_get_data_stub.h"

#include "iam_logger.h"
#include "iam_common_defines.h"

#define LOG_LABEL OHOS::UserIam::Common::LABEL_PIN_AUTH_SDK

namespace OHOS {
namespace UserIam {
namespace PinAuth {
int32_t InputerGetDataStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    IAM_LOGI("cmd = %{public}u, flags = %{public}d", code, option.GetFlags());
    if (InputerGetDataStub::GetDescriptor() != data.ReadInterfaceToken()) {
        IAM_LOGE("descriptor is not matched");
        return UserAuth::FAIL;
    }

    if (code == InputerGetData::ON_GET_DATA) {
        OnGetDataStub(data, reply);
        return UserAuth::SUCCESS;
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

void InputerGetDataStub::OnGetDataStub(MessageParcel &data, MessageParcel &reply)
{
    int32_t authSubType;
    std::vector<uint8_t> salt;

    if (!data.ReadInt32(authSubType)) {
        IAM_LOGE("failed to read authSubType");
        return;
    }
    if (!data.ReadUInt8Vector(&salt)) {
        IAM_LOGE("failed to read salt");
        return;
    }
    sptr<IRemoteObject> obj = data.ReadRemoteObject();
    if (obj == nullptr) {
        IAM_LOGE("failed to read remote object");
        return;
    }
    sptr<InputerSetData> inputerSetData = iface_cast<InputerSetData>(obj);
    if (inputerSetData == nullptr) {
        IAM_LOGE("inputerSetData is nullptr");
        return;
    }

    OnGetData(authSubType, salt, inputerSetData.GetRefPtr());
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
