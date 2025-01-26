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

#include "pin_auth_executor_callback_hdi_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "parcel.h"

#include "iam_common_defines.h"
#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#include "mock_iall_in_one_executor_fuzzer.h"
#include "mock_icollector_executor_fuzzer.h"
#include "mock_iexecutor_callback_fuzzer.h"
#include "mock_inputer_get_data_fuzzer.h"

#include "pin_auth_executor_callback_hdi.h"
#include "pin_auth_hdi.h"

#define LOG_TAG "PIN_AUTH_SA"

#undef private

using namespace std;
using namespace OHOS::UserIam::Common;

namespace OHOS {
namespace UserIam {
namespace PinAuth {
namespace {

const uint64_t SCHEDULE_ID = 123;
const uint32_t TOKEN_ID = 2;
auto allInOneExecutorProxy_ = sptr<IAllInOneExecutor>(new (std::nothrow) MockIAllInOneExecutorFuzzer);
auto allInOneHdi_ = Common::MakeShared<PinAuthAllInOneHdi>(allInOneExecutorProxy_);
auto collectorExecutorProxy_ = sptr<ICollector>(new (std::nothrow) MockICollectorExecutorFuzzer);
auto collectorHdi_ = Common::MakeShared<PinAuthCollectorHdi>(collectorExecutorProxy_);
auto frameWorkCallback_ = Common::MakeShared<MockIExecutorCallbackFuzzer>();
std::shared_ptr<PinAuthExecutorCallbackHdi> pinAuthExecutorCallbackHdi_(nullptr);

void InitPinAuthExecutorCallbackHdi(Parcel &parcel)
{
    const UserAuth::ExecutorParam executorParam = {
        .tokenId = TOKEN_ID,
        .authIntent = 0,
        .scheduleId = SCHEDULE_ID,
    };
    GetDataMode mode = static_cast<GetDataMode>(parcel.ReadInt32());
    if (parcel.ReadBool()) {
        pinAuthExecutorCallbackHdi_ = Common::MakeShared<PinAuthExecutorCallbackHdi>(
            frameWorkCallback_, allInOneHdi_, executorParam, mode);
    } else {
        pinAuthExecutorCallbackHdi_ = Common::MakeShared<PinAuthExecutorCallbackHdi>(
            frameWorkCallback_, collectorHdi_, executorParam, mode);
    }
}

void FuzzDoVibrator(Parcel &parcel)
{
    IAM_LOGI("begin");
    if (pinAuthExecutorCallbackHdi_ != nullptr) {
        pinAuthExecutorCallbackHdi_->DoVibrator();
    }
    IAM_LOGI("end");
}

void FuzzOnResult(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t code = UserAuth::FAIL;
    std::vector<uint8_t> extraInfo;
    FillFuzzUint8Vector(parcel, extraInfo);
    if (pinAuthExecutorCallbackHdi_ != nullptr) {
        pinAuthExecutorCallbackHdi_->OnResult(code, extraInfo);
    }
    IAM_LOGI("end");
}

void FuzzOnGetData(Parcel &parcel)
{
    IAM_LOGI("begin");
    std::vector<uint8_t> algoParameter;
    uint64_t authSubType = static_cast<uint64_t>(parcel.ReadUint32());
    uint32_t algoVersion = parcel.ReadUint32();
    std::vector<uint8_t> challenge;
    std::string pinComplexityReg;
    FillFuzzUint8Vector(parcel, algoParameter);
    FillFuzzUint8Vector(parcel, challenge);
    uint32_t tokenId = 1;
    auto inputer = sptr<InputerGetData>(new (std::nothrow) MockInputerGetDataFuzzer());
    pinAuthExecutorCallbackHdi_->tokenId_ = tokenId;
    PinAuthManager::GetInstance().RegisterInputer(tokenId, inputer);
    if (pinAuthExecutorCallbackHdi_ != nullptr) {
        pinAuthExecutorCallbackHdi_->OnGetData(algoParameter, authSubType, algoVersion, challenge,
            pinComplexityReg);
    }
    IAM_LOGI("end");
}

void FuzzOnTip(Parcel &parcel)
{
    IAM_LOGI("begin");
    uint32_t tip = parcel.ReadUint32();
    std::vector<uint8_t> extraInfo;
    FillFuzzUint8Vector(parcel, extraInfo);
    if (pinAuthExecutorCallbackHdi_ != nullptr) {
        pinAuthExecutorCallbackHdi_->OnTip(tip, extraInfo);
    }
    IAM_LOGI("end");
}

void FuzzOnMessage(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t destRole = parcel.ReadInt32();
    std::vector<uint8_t> msg;
    FillFuzzUint8Vector(parcel, msg);
    if (pinAuthExecutorCallbackHdi_ != nullptr) {
        pinAuthExecutorCallbackHdi_->OnMessage(destRole, msg);
    }
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FuzzOnResult);
FuzzFunc *g_fuzzFuncs[] = {FuzzDoVibrator, FuzzOnResult, FuzzOnGetData, FuzzOnTip, FuzzOnMessage};

void PinAuthExecutorCallbackHdiFuzzTest(const uint8_t *data, size_t size)
{
    Parcel parcel;
    parcel.WriteBuffer(data, size);
    parcel.RewindRead(0);
    InitPinAuthExecutorCallbackHdi(parcel);
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
    OHOS::UserIam::PinAuth::PinAuthExecutorCallbackHdiFuzzTest(data, size);
    return 0;
}
