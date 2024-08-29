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

#ifndef INPUTER_GET_DATA_STUB_H
#define INPUTER_GET_DATA_STUB_H

#include "inputer_get_data.h"

#include "iremote_stub.h"
#include "message_parcel.h"
#include "nocopyable.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
class InputerGetDataStub : public IRemoteStub<InputerGetData>, public NoCopyable {
public:
    InputerGetDataStub() = default;
    ~InputerGetDataStub() override = default;
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    void OnGetDataStub(MessageParcel &data, MessageParcel &reply);
    bool ReadInputerGetDataParam(MessageParcel &data, InputerGetDataParam &getDataParam);
};
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
#endif // INPUTER_GET_DATA_STUB_H