/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef PINAUTH_IINPUTERDATA_IMPL_H
#define PINAUTH_IINPUTERDATA_IMPL_H

#include <memory>
#include <vector>
#include <stdint.h>
#include <mutex>
#include "i_inputer_data.h"
#include "iremote_inputer_data.h"
#include "refbase.h"

namespace OHOS {
namespace UserIAM {
namespace PinAuth {
const int32_t OUT_LENGTH = 64;
const int32_t SCRYPT_N = 32768;
const int32_t SCRYPT_R = 3;
const int32_t SCRYPT_P = 1;

class InputerDataImpl : public IInputerData {
public:
    explicit InputerDataImpl(std::vector<uint8_t> salt, sptr<IRemoteInputerData> remoteInputerData);
    ~InputerDataImpl() override;
    void OnSetData(int32_t authSubType, std::vector<uint8_t> data) override;

private:
    std::vector<uint8_t> salt_;
    sptr<IRemoteInputerData> remoteInputerData_;
private:
    void getScrypt(std::vector<uint8_t> data, std::vector<uint8_t> &scrypt);
};
} // namespace PinAuth
} // namespace UserIAM
} // namespace OHOS

#endif // PINAUTH_IINPUTERDATA_H
