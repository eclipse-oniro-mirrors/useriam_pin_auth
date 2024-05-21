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

#include "pin_auth_verifier_hdi_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "parcel.h"

#include "iam_common_defines.h"
#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#include "mock_iverifier_executor_fuzzer.h"
#include "mock_iexecutor_callback_fuzzer.h"

#include "pin_auth_verifier_hdi.h"
#include "pin_auth_hdi.h"

#define LOG_TAG "PIN_AUTH_SA"

#undef private

using namespace std;
using namespace OHOS::UserIam::Common;

namespace OHOS {
namespace UserIam {
namespace PinAuth {
namespace {

static uint64_t g_index = 0;
const uint64_t SCHEDULE_ID = 123;
const uint32_t FUZZ_NUM = 2;
auto executorProxy_ = sptr<IVerifier>(new (std::nothrow) MockIVerifierExecutorFuzzer);
std::shared_ptr<PinAuthVerifierHdi> hdi_(nullptr);
std::shared_ptr<UserAuth::IExecuteCallback> iExecutorCallback_ = Common::MakeShared<MockIExecutorCallbackFuzzer>();

void InitPinAuthVerifierHdi(Parcel &parcel)
{
    hdi_ = Common::MakeShared<PinAuthVerifierHdi>((g_index % FUZZ_NUM) == 0 ? nullptr : executorProxy_);
}

void FuzzGetExecutorInfo(Parcel &parcel)
{
    IAM_LOGI("begin");
    UserAuth::ExecutorInfo info;
    if (hdi_ != nullptr) {
        hdi_->GetExecutorInfo(info);
    }
    IAM_LOGI("end");
}

void FuzzOnRegisterFinish(Parcel &parcel)
{
    IAM_LOGI("begin");
    std::vector<uint64_t> templateIdList;
    std::vector<uint8_t> frameworkPublicKey;
    std::vector<uint8_t> extraInfo;
    FillFuzzUint64Vector(parcel, templateIdList);
    FillFuzzUint8Vector(parcel, frameworkPublicKey);
    FillFuzzUint8Vector(parcel, extraInfo);
    if (hdi_ != nullptr) {
        hdi_->OnRegisterFinish(templateIdList, frameworkPublicKey, extraInfo);
    }
    IAM_LOGI("end");
}

void FuzzSendMessage(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t srcRole = parcel.ReadInt32();
    std::vector<uint8_t> msg;
    FillFuzzUint8Vector(parcel, msg);
    if (hdi_ != nullptr) {
        hdi_->SendMessage(SCHEDULE_ID, srcRole, msg);
    }
    IAM_LOGI("end");
}

void FuzzAuthenticate(Parcel &parcel)
{
    IAM_LOGI("begin");
    std::vector<uint64_t> templateIdList;
    std::vector<uint8_t> extraInfo;
    FillFuzzUint64Vector(parcel, templateIdList);
    FillFuzzUint8Vector(parcel, extraInfo);
    UserAuth::AuthenticateParam parm = {
        .tokenId = parcel.ReadUint32(),
        .templateIdList = templateIdList,
        .extraInfo = extraInfo,
        .endAfterFirstFail = parcel.ReadBool(),
    };
    if (hdi_ != nullptr) {
        hdi_->Authenticate(SCHEDULE_ID, parm, iExecutorCallback_);
    }
    IAM_LOGI("end");
}

void FuzzCancel(Parcel &parcel)
{
    IAM_LOGI("begin");
    if (hdi_ != nullptr) {
        hdi_->Cancel(SCHEDULE_ID);
    }
    IAM_LOGI("end");
}

void FuzzNotifyCollectorReady(Parcel &parcel)
{
    IAM_LOGI("begin");
    if (hdi_ != nullptr) {
        hdi_->NotifyCollectorReady(SCHEDULE_ID);
    }
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FuzzGetExecutorInfo);
FuzzFunc *g_fuzzFuncs[] = {FuzzGetExecutorInfo, FuzzOnRegisterFinish, FuzzSendMessage,
    FuzzAuthenticate, FuzzCancel, FuzzNotifyCollectorReady};

void PinAuthVerifierHdiFuzzTest(const uint8_t *data, size_t size)
{
    Parcel parcel;
    parcel.WriteBuffer(data, size);
    parcel.RewindRead(0);
    InitPinAuthVerifierHdi(parcel);
    uint32_t index = g_index++ % (sizeof(g_fuzzFuncs) / sizeof(FuzzFunc *));
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
    OHOS::UserIam::PinAuth::PinAuthVerifierHdiFuzzTest(data, size);
    return 0;
}
