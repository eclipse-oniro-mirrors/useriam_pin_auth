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

#include "i_inputer_stub.h"

#include "ipc_object_stub.h"
#include "iremote_broker.h"
#include "message_parcel.h"

#include "iam_logger.h"
#include "iam_common_defines.h"
#include "iremote_inputer.h"
#include "iremote_inputer_data.h"
#include "i_inputer.h"
#include "inputer_impl.h"
#include "inputer_data_impl.h"

#define LOG_LABEL OHOS::UserIam::Common::LABEL_PIN_AUTH_SDK

namespace OHOS {
namespace UserIam {
namespace PinAuth {
IInputerStub::IInputerStub() = default;
IInputerStub::~IInputerStub() = default;

void IInputerStub::HandlerOnGetData(MessageParcel &data, MessageParcel &reply)
{
    int32_t authSubType = data.ReadInt32();
    IAM_LOGI("start, authSubType = %{public}d", authSubType);
    std::vector<uint8_t> salt;
    data.ReadUInt8Vector(&salt);
    sptr<IRemoteObject> remote = data.ReadRemoteObject();
    if (remote == nullptr) {
        IAM_LOGE("remote is nullptr");
        return;
    }
    sptr<IRemoteInputerData> inputerData = iface_cast<IRemoteInputerData>(remote);
    if (inputerData == nullptr) {
        IAM_LOGE("inputerData is nullptr");
        return;
    }
    OnGetData(authSubType, salt, inputerData.GetRefPtr());
}

int32_t IInputerStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    IAM_LOGI("start code = %{public}u", code);
    if (IInputerStub::GetDescriptor() != data.ReadInterfaceToken()) {
        IAM_LOGE("descriptor is not equal");
        return UserAuth::FAIL;
    }

    switch (code) {
        case static_cast<int32_t>(IRemoteInputer::ON_GET_DATA):
            HandlerOnGetData(data, reply);
            return UserAuth::SUCCESS;
        default:
            IAM_LOGI("default");
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return UserAuth::SUCCESS;
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
