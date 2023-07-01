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

#include "pin_auth_stub.h"

#include "iam_logger.h"
#include "iam_common_defines.h"

#define LOG_LABEL UserIam::Common::LABEL_PIN_AUTH_SA

namespace OHOS {
namespace UserIam {
namespace PinAuth {
int32_t PinAuthStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    IAM_LOGI("cmd = %{public}u, flags = %{public}d", code, option.GetFlags());
    if (PinAuthStub::GetDescriptor() != data.ReadInterfaceToken()) {
        IAM_LOGE("descriptor is not matched");
        return UserAuth::GENERAL_ERROR;
    }
    switch (code) {
        case PinAuthInterfaceCode::REGISTER_INPUTER:
            RegisterInputerStub(data, reply);
            return UserAuth::SUCCESS;
        case PinAuthInterfaceCode::UNREGISTER_INPUTER:
            UnRegisterInputerStub(data, reply);
            return UserAuth::SUCCESS;
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

void PinAuthStub::RegisterInputerStub(MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("start");
    sptr<IRemoteObject> obj = data.ReadRemoteObject();
    if (obj == nullptr) {
        IAM_LOGE("failed to read remote object");
        return;
    }
    sptr<InputerGetData> inputer = iface_cast<InputerGetData>(obj);
    if (inputer == nullptr) {
        IAM_LOGE("inputer is nullptr");
        return;
    }
    bool ret = RegisterInputer(inputer);
    if (!reply.WriteBool(ret)) {
        IAM_LOGE("failed to write result");
    }
}

void PinAuthStub::UnRegisterInputerStub(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    (void)reply;
    IAM_LOGI("start");
    UnRegisterInputer();
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS