/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "inputer_data_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "parcel.h"

#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#include "i_inputer_data_impl.h"
#include "pin_auth_hdi.h"

#define LOG_TAG "PIN_AUTH_SA"

#undef private

using namespace std;
using namespace OHOS::UserIam::Common;

namespace OHOS {
namespace UserIam {
namespace PinAuth {
namespace {
const uint32_t SCHEDULE_ID = 123;
sptr<IAllInOneExecutor> executorProxy(nullptr);
std::shared_ptr<PinAuthAllInOneHdi> pinAuthAllInOneHdi_ = Common::MakeShared<PinAuthAllInOneHdi>(executorProxy);
auto g_service = new (std::nothrow) IInputerDataImpl(SCHEDULE_ID, pinAuthAllInOneHdi_);

void FuzzRegisterInputer(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t authSubType = parcel.ReadInt32();
    std::vector<uint8_t> data;
    int32_t errorCode = parcel.ReadInt32();
    FillFuzzUint8Vector(parcel, data);
    if (g_service != nullptr) {
        g_service->OnSetData(authSubType, data, errorCode);
    }
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FuzzRegisterInputer);
FuzzFunc *g_fuzzFuncs[] = {FuzzRegisterInputer};

void InputerDataFuzzTest(const uint8_t *data, size_t size)
{
    Parcel parcel;
    parcel.WriteBuffer(data, size);
    parcel.RewindRead(0);
    uint32_t index = parcel.ReadUint32() % (sizeof(g_fuzzFuncs) / sizeof(FuzzFunc *));
    auto fuzzFunc = g_fuzzFuncs[index];
    fuzzFunc(parcel);
    return;
}
} // namespace
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::UserIam::PinAuth::InputerDataFuzzTest(data, size);
    return 0;
}