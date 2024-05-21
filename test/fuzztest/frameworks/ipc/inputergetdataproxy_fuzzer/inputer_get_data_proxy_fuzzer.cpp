/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "inputer_get_data_proxy_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "inputer_get_data.h"
#include "parcel.h"

#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "i_inputer_data_impl.h"
#include "pin_auth_all_in_one_hdi.h"

#include "inputer_get_data_proxy.h"

#define LOG_TAG "PIN_AUTH_SA"

#undef private

using namespace std;
using namespace OHOS::UserIam::Common;

namespace OHOS {
namespace UserIam {
namespace PinAuth {
namespace {

constexpr uint64_t SCHEDULE_ID = 123;
bool InputerGetDataProxyFuzzTest(const uint8_t *rawData, size_t size)
{
    IAM_LOGI("start");
    if (rawData == nullptr) {
        return false;
    }
    Parcel parcel;
    parcel.WriteBuffer(rawData, size);
    parcel.RewindRead(0);
    std::vector<uint8_t> algoParmeter;
    std::vector<uint8_t> challenge;
    auto hdi = Common::MakeShared<PinAuthAllInOneHdi>(nullptr);
    sptr<IInputerDataImpl> inputerSetData(new (std::nothrow) IInputerDataImpl(SCHEDULE_ID, hdi));
    FillFuzzUint8Vector(parcel, algoParmeter);
    FillFuzzUint8Vector(parcel, challenge);
    InputerGetDataParam param = {
        .mode = static_cast<GetDataMode>(parcel.ReadInt32()),
        .authSubType = parcel.ReadInt32(),
        .algoVersion = parcel.ReadInt32(),
        .algoParameter = algoParmeter,
        .challenge = challenge,
        .inputerSetData = inputerSetData,
    };
    std::shared_ptr<InputerGetDataProxy> inputerGetDataProxy = Common::MakeShared<InputerGetDataProxy>(nullptr);
    inputerGetDataProxy->OnGetData(param);
    return true;
}
} // namespace
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::UserIam::PinAuth::InputerGetDataProxyFuzzTest(data, size);
    return 0;
}