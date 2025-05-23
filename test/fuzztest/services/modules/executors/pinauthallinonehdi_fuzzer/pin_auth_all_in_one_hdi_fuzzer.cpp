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

#include "pin_auth_all_in_one_hdi_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "parcel.h"

#include "iam_common_defines.h"
#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#include "mock_iall_in_one_executor_fuzzer.h"
#include "mock_iexecutor_callback_fuzzer.h"

#include "pin_auth_all_in_one_hdi.h"
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
auto executorProxy_ = sptr<IAllInOneExecutor>(new (std::nothrow) MockIAllInOneExecutorFuzzer);
std::shared_ptr<PinAuthAllInOneHdi> hdi_(nullptr);
std::shared_ptr<UserAuth::IExecuteCallback> iExecutorCallback_ = Common::MakeShared<MockIExecutorCallbackFuzzer>();

void InitPinAuthAllInOneHdi(Parcel &parcel)
{
    static_cast<void>(parcel);
    hdi_ = Common::MakeShared<PinAuthAllInOneHdi>(executorProxy_);
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

void FuzzEnroll(Parcel &parcel)
{
    IAM_LOGI("begin");
    std::vector<uint8_t> extraInfo;
    FillFuzzUint8Vector(parcel, extraInfo);
    UserAuth::EnrollParam parm = {
        .tokenId = parcel.ReadUint32(),
        .extraInfo = extraInfo,
    };
    hdi_->SetAuthType(AuthType::PIN);
    if (hdi_ != nullptr) {
        hdi_->Enroll(SCHEDULE_ID, parm, iExecutorCallback_);
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
    hdi_->SetAuthType(AuthType::PIN);
    if (hdi_ != nullptr) {
        hdi_->Authenticate(SCHEDULE_ID, parm, iExecutorCallback_);
    }
    IAM_LOGI("end");
}

void FuzzOnSetData(Parcel &parcel)
{
    IAM_LOGI("begin");
    uint64_t authSubType = parcel.ReadUint32();
    std::vector<uint8_t> data;
    int32_t errorCode = parcel.ReadInt32();
    FillFuzzUint8Vector(parcel, data);
    if (hdi_ != nullptr) {
        hdi_->OnSetData(SCHEDULE_ID, authSubType, data, errorCode);
    }
    IAM_LOGI("end");
}

void FuzzDelete(Parcel &parcel)
{
    IAM_LOGI("begin");
    std::vector<uint64_t> templateIdList;
    FillFuzzUint64Vector(parcel, templateIdList);
    if (hdi_ != nullptr) {
        hdi_->Delete(templateIdList);
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

void FuzzGetProperty(Parcel &parcel)
{
    IAM_LOGI("begin");
    std::vector<uint64_t> templateIdList;
    std::vector<UserAuth::Attributes::AttributeKey> keys;
    std::string enrollmentProgress;
    std::string sensorInfo;

    FillFuzzUint64Vector(parcel, templateIdList);
    FillFuzzString(parcel, enrollmentProgress);
    FillFuzzString(parcel, sensorInfo);
    UserAuth::Property property = {
        .authSubType = parcel.ReadUint32(),
        .lockoutDuration = parcel.ReadInt32(),
        .remainAttempts = parcel.ReadInt32(),
        .enrollmentProgress = enrollmentProgress,
        .sensorInfo = sensorInfo,
        .nextFailLockoutDuration = parcel.ReadInt32(),
    };
    if (hdi_ != nullptr) {
        hdi_->GetProperty(templateIdList, keys, property);
    }
    IAM_LOGI("end");
}

void FuzzConvertAttributeKeyToPropertyType(Parcel &parcel)
{
    IAM_LOGI("begin");
    const UserAuth::Attributes::AttributeKey in = static_cast<UserAuth::Attributes::AttributeKey>(parcel.ReadUint32());
    int32_t out;
    if (hdi_ != nullptr) {
        hdi_->ConvertAttributeKeyToPropertyType(in, out);
    }
    IAM_LOGI("end");
}

void FuzzSetAuthType(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t authType = parcel.ReadInt32();
    if (hdi_ != nullptr) {
        hdi_->SetAuthType(authType);
    }
    IAM_LOGI("end");
}

void FuzzAbandon(Parcel &parcel)
{
    IAM_LOGI("begin");
    std::vector<uint8_t> extraInfo;
    FillFuzzUint8Vector(parcel, extraInfo);
    UserAuth::DeleteParam parm = {
        .tokenId = parcel.ReadUint32(),
        .userId = parcel.ReadInt32(),
        .templateId = parcel.ReadUint64(),
        .extraInfo = extraInfo,
    };
    hdi_->SetAuthType(AuthType::PIN);
    if (hdi_ != nullptr) {
        hdi_->Abandon(SCHEDULE_ID, parm, iExecutorCallback_);
    }
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FuzzGetExecutorInfo);
FuzzFunc *g_fuzzFuncs[] = {FuzzGetExecutorInfo, FuzzOnRegisterFinish, FuzzSendMessage, FuzzEnroll, FuzzAuthenticate,
    FuzzOnSetData, FuzzDelete, FuzzCancel, FuzzGetProperty, FuzzConvertAttributeKeyToPropertyType, FuzzSetAuthType,
    FuzzAbandon};

void PinAuthAllInOneHdiFuzzTest(const uint8_t *data, size_t size)
{
    Parcel parcel;
    parcel.WriteBuffer(data, size);
    parcel.RewindRead(0);
    InitPinAuthAllInOneHdi(parcel);
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
    OHOS::UserIam::PinAuth::PinAuthAllInOneHdiFuzzTest(data, size);
    return 0;
}
