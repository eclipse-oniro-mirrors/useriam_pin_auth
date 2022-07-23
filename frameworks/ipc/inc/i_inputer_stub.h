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

#ifndef IINPUTER_STUB_H
#define IINPUTER_STUB_H

#include <cstdint>
#include "i_inputer.h"
#include "iremote_inputer.h"
#include "iremote_stub.h"
#include "nocopyable.h"
#include "refbase.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
class IInputerStub : public IRemoteStub<IRemoteInputer>, public NoCopyable {
public:
    explicit IInputerStub(std::shared_ptr<IInputer> inputer);
    ~IInputerStub();
    void OnGetData(int32_t authSubType, std::vector<uint8_t> salt, sptr<IRemoteInputerData> inputerData) override;
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    std::shared_ptr<IInputer> inputer_;
    void HandlerOnGetData(MessageParcel &data, MessageParcel &reply);
};
}  // namespace PinAuth
}  // namespace UserIam
}  // namespace OHOS

#endif  // IINPUTER_STUB_H