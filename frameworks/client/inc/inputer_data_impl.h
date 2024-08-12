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

#ifndef INPUTER_DATA_IMPL_H
#define INPUTER_DATA_IMPL_H

#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

#include "refbase.h"

#include "iam_common_defines.h"
#include "i_inputer_data.h"
#include "inputer_get_data.h"
#include "inputer_set_data.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
class InputerDataImpl : public IInputerData {
public:
    InputerDataImpl(const InputerGetDataParam &param);
    ~InputerDataImpl() override = default;
    void OnSetData(int32_t authSubType, std::vector<uint8_t> data) override;

private:
    bool GetSha256(const std::vector<uint8_t> &data, std::vector<uint8_t> &out);
    void GetPinData(
        int32_t authSubType, const std::vector<uint8_t> &dataIn, std::vector<uint8_t> &dataOut, int32_t &errorCode);
    void GetRecoveryKeyData(const std::vector<uint8_t> &dataIn, std::vector<uint8_t> &dataOut, int32_t &errorCode);
    void OnSetDataInner(int32_t authSubType, std::vector<uint8_t> &setData, int32_t errorCode);
    int32_t CheckPinComplexity(int32_t authSubType, const std::vector<uint8_t> &data);
    bool CheckSpecialPinComplexity(std::vector<uint8_t> &input);
    bool CheckEdmPinComplexity(int32_t authSubType, std::vector<uint8_t> &input);
    bool CheckPinComplexityByReg(std::vector<uint8_t> &input, const std::string &complexityReg);

    GetDataMode mode_ = GET_DATA_MODE_NONE;
    uint32_t algoVersion_ = 0;
    std::vector<uint8_t> algoParameter_;
    sptr<InputerSetData> inputerSetData_;
    std::string complexityReg_;
    int32_t userId_;
};
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
#endif // INPUTER_DATA_IMPL_H
