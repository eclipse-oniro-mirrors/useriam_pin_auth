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

#include "pin_auth_driver_hdi_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "parcel.h"

#include "iam_common_defines.h"
#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#include "mock_pin_auth_interface_adapter_fuzzer.h"

#include "pin_auth_driver_hdi.h"

#define LOG_TAG "PIN_AUTH_SA"

#undef private

using namespace std;
using namespace OHOS::UserIam::Common;

namespace OHOS {
namespace UserIam {
namespace PinAuth {
namespace {

std::shared_ptr<PinAuthDriverHdi> pinAuthDriverHdi_(nullptr);

void InitPinAuthDriverHdi(Parcel &parcel)
{
    static_cast<void>(parcel);
    std::shared_ptr<PinAuthInterfaceAdapter> adapter = Common::MakeShared<MockPinAuthInterfaceAdapterFuzzer>();
    pinAuthDriverHdi_ = Common::MakeShared<PinAuthDriverHdi>(adapter);
    IAM_LOGI("end");
}

void FuzzGetExecutorList(Parcel &parcel)
{
    IAM_LOGI("begin");
    static_cast<void>(parcel);
    std::vector<std::shared_ptr<UserAuth::IAuthExecutorHdi>> executorList;
    if (pinAuthDriverHdi_ != nullptr) {
        pinAuthDriverHdi_->GetExecutorList(executorList);
    }
    IAM_LOGI("end");
}

void FuzzOnHdiDisconnect(Parcel &parcel)
{
    IAM_LOGI("begin");
    static_cast<void>(parcel);
    if (pinAuthDriverHdi_ != nullptr) {
        pinAuthDriverHdi_->OnHdiDisconnect();
    }
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FuzzGetExecutorList);
FuzzFunc *g_fuzzFuncs[] = {FuzzGetExecutorList, FuzzOnHdiDisconnect};

void PinAuthDriverHdiFuzzTest(const uint8_t *data, size_t size)
{
    Parcel parcel;
    parcel.WriteBuffer(data, size);
    parcel.RewindRead(0);
    InitPinAuthDriverHdi(parcel);
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
    OHOS::UserIam::PinAuth::PinAuthDriverHdiFuzzTest(data, size);
    return 0;
}
