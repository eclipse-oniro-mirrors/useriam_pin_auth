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

#include "inputer_set_data_stub.h"

#include "iam_logger.h"
#include "iam_common_defines.h"

#define LOG_TAG "PIN_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace PinAuth {

// When true is passed into IRemoteStub, sa will process request serially.
InputerSetDataStub::InputerSetDataStub() : IRemoteStub(true) {};

int32_t InputerSetDataStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    IAM_LOGI("cmd = %{public}u, flags = %{public}d", code, option.GetFlags());
    if (InputerSetDataStub::GetDescriptor() != data.ReadInterfaceToken()) {
        IAM_LOGE("descriptor is not matched");
        return UserAuth::GENERAL_ERROR;
    }
    switch (code) {
        case InputerSetDataInterfaceCode::ON_SET_DATA:
            OnSetDataStub(data, reply);
            return UserAuth::SUCCESS;
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

void InputerSetDataStub::OnSetDataStub(MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("start");
    int32_t subType;
    std::vector<uint8_t> param;
    int32_t errorCode;

    if (!data.ReadInt32(subType)) {
        IAM_LOGE("failed to read subType");
        return;
    }
    if (!data.ReadUInt8Vector(&param)) {
        IAM_LOGE("failed to read param");
        return;
    }
    if (!data.ReadInt32(errorCode)) {
        IAM_LOGE("failed to read errorCode");
        return;
    }

    OnSetData(subType, param, errorCode);
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
