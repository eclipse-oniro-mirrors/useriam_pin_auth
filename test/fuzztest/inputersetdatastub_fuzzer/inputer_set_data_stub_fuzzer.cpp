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

#include "inputer_set_data_stub_fuzzer.h"

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

constexpr uint32_t SCHEDULE_ID = 123;
constexpr uint32_t INPUTER_SET_DATA_CODE_MIN = 1;
constexpr uint32_t INPUTER_SET_DATA_CODE_MAX = 1;
const std::u16string INPUTER_SET_DATA_INTERFACE_TOKEN = u"ohos.PinAuth.InputerSetData";

bool InputerSetDataStubFuzzTest(const uint8_t *rawData, size_t size)
{
    IAM_LOGI("start");
    if (rawData == nullptr) {
        return false;
    }

    sptr<IAllInOneExecutor> executorProxy(nullptr);
    std::shared_ptr<PinAuthAllInOneHdi> pinAuthExecutorHdi_ = Common::MakeShared<PinAuthAllInOneHdi>(executorProxy);
    IInputerDataImpl iInputerDataImpl(SCHEDULE_ID, pinAuthExecutorHdi_);
    for (uint32_t code = INPUTER_SET_DATA_CODE_MIN; code <= INPUTER_SET_DATA_CODE_MAX; code++) {
        MessageParcel data;
        MessageParcel reply;
        MessageOption optionSync = MessageOption::TF_SYNC;
        MessageOption optionAsync = MessageOption::TF_ASYNC;
        // Sync
        data.WriteInterfaceToken(INPUTER_SET_DATA_INTERFACE_TOKEN);
        data.WriteBuffer(rawData, size);
        data.RewindRead(0);
        (void)iInputerDataImpl.OnRemoteRequest(code, data, reply, optionSync);
        // Async
        data.WriteInterfaceToken(INPUTER_SET_DATA_INTERFACE_TOKEN);
        data.WriteBuffer(rawData, size);
        data.RewindRead(0);
        (void)iInputerDataImpl.OnRemoteRequest(code, data, reply, optionAsync);
    }
    return true;
}
} // namespace
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::UserIam::PinAuth::InputerSetDataStubFuzzTest(data, size);
    return 0;
}
