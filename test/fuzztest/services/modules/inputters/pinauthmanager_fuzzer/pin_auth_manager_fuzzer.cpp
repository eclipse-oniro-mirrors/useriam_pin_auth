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

#include "pin_auth_manager_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "parcel.h"

#include "iam_common_defines.h"
#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#include "mock_inputer_get_data_fuzzer.h"

#include "pin_auth_manager.h"

#define LOG_TAG "PIN_AUTH_SA"

#undef private

using namespace std;
using namespace OHOS::UserIam::Common;

namespace OHOS {
namespace UserIam {
namespace PinAuth {
namespace {

void FuzzRegisterInputer(Parcel &parcel)
{
    IAM_LOGI("begin");
    uint32_t tokenId = parcel.ReadUint32();
    sptr<InputerGetData> inputer(nullptr);
    if (parcel.ReadBool()) {
        inputer = sptr<InputerGetData>(new (std::nothrow) MockInputerGetDataFuzzer());
    }
    PinAuthManager::GetInstance().RegisterInputer(tokenId, inputer);
    PinAuthManager::GetInstance().RegisterInputer(tokenId, inputer);

    PinAuthManager::GetInstance().UnRegisterInputer(tokenId);
    IAM_LOGI("end");
}

void FuzzUnRegisterInputer(Parcel &parcel)
{
    IAM_LOGI("begin");
    uint32_t tokenId = parcel.ReadUint32();
    sptr<InputerGetData> inputer(nullptr);
    if (parcel.ReadBool()) {
        inputer = sptr<InputerGetData>(new (std::nothrow) MockInputerGetDataFuzzer());
    }
    PinAuthManager::GetInstance().UnRegisterInputer(tokenId);
    PinAuthManager::GetInstance().RegisterInputer(tokenId, inputer);

    PinAuthManager::GetInstance().UnRegisterInputer(tokenId);
    IAM_LOGI("end");
}

void FuzzGetInputerLock(Parcel &parcel)
{
    IAM_LOGI("begin");
    uint32_t tokenId = parcel.ReadUint32();
    auto inputer = sptr<InputerGetData>(new (std::nothrow) MockInputerGetDataFuzzer());
    PinAuthManager::GetInstance().RegisterInputer(tokenId, inputer);
    PinAuthManager::GetInstance().GetInputerLock(tokenId);
    PinAuthManager::GetInstance().UnRegisterInputer(tokenId);
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FuzzRegisterInputer);
FuzzFunc *g_fuzzFuncs[] = {FuzzRegisterInputer, FuzzUnRegisterInputer, FuzzGetInputerLock};

void PinAuthManagerFuzzTest(const uint8_t *data, size_t size)
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
    OHOS::UserIam::PinAuth::PinAuthManagerFuzzTest(data, size);
    return 0;
}
