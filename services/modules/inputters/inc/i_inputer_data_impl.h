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

#ifndef I_INPUTER_DATA_IMPL_H
#define I_INPUTER_DATA_IMPL_H

#include <cstdint>
#include <mutex>
#include <vector>

#include "inputer_set_data_stub.h"
#include "pin_auth_executor_hdi.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
class IInputerDataImpl : public InputerSetDataStub {
public:
    IInputerDataImpl(uint64_t scheduleId, std::shared_ptr<PinAuthExecutorHdi> hdi);
    ~IInputerDataImpl() override;
    void OnSetData(int32_t authSubType, std::vector<uint8_t> data, int32_t errorCode) override;

private:
    std::mutex mutex_;
    uint64_t scheduleId_ {0};
    std::shared_ptr<PinAuthExecutorHdi> hdi_ {nullptr};
};
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS

#endif // I_INPUTER_DATA_IMPL_H
