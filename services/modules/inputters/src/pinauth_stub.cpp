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

#include "pinauth_stub.h"

#include "ipc_object_stub.h"
#include "iremote_broker.h"
#include "message_parcel.h"

#include "iam_logger.h"
#include "iremote_inputer.h"
#include "iremote_pinauth.h"
#include "pinauth_defines.h"

#define LOG_LABEL UserIAM::Common::LABEL_PIN_AUTH_SA

namespace OHOS {
namespace UserIAM {
namespace PinAuth {
PinAuthStub::PinAuthStub()
{
    IAM_LOGI("start");
}

PinAuthStub::~PinAuthStub()
{
    IAM_LOGI("start");
}

int32_t PinAuthStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    IAM_LOGI("start");
    std::u16string descripter = PinAuthStub::GetDescriptor();
    std::u16string remoteDescripter = data.ReadInterfaceToken();
    if (descripter != remoteDescripter) {
        return FAIL;
    }
    switch (code) {
        case static_cast<int32_t>(IRemotePinAuth::REGISTER_INPUTER):
            HandlerRegisterInputer(data, reply);
            return SUCCESS;
        case static_cast<int32_t>(IRemotePinAuth::UNREGISTER_INPUTER):
            HandlerUnRegisterInputer(data, reply);
            return SUCCESS;
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

void PinAuthStub::HandlerRegisterInputer(MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("start");
    sptr<IRemoteObject> remote = data.ReadRemoteObject();
    if (remote == nullptr) {
        return;
    }
    sptr<IRemoteInputer> inputer = iface_cast<IRemoteInputer>(remote);
    if (inputer == nullptr) {
        return;
    }
    bool ret = RegisterInputer(inputer);
    if (!reply.WriteBool(ret)) {
        IAM_LOGE("write inputer fail");
        return;
    }
}

void PinAuthStub::HandlerUnRegisterInputer(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    (void)reply;
    IAM_LOGI("start");
    UnRegisterInputer();
}
} // namespace PinAuth
} // namespace UserIAM
} // namespace OHOS