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

#include "pin_auth_service_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "inputer_get_data.h"
#include "parcel.h"

#include "iam_fuzz_test.h"
#include "iam_logger.h"

#include "pin_auth_service.h"

#define LOG_LABEL UserIam::Common::LABEL_FACE_AUTH_SA

#undef private

using namespace std;
using namespace OHOS::UserIAM::Common;

namespace OHOS {
namespace UserIam {
namespace PinAuth {
namespace {
class DummyRemoteInputer : public InputerGetData {
public:
    void OnGetData(int32_t authSubType, const std::vector<uint8_t> &salt, const sptr<InputerSetData> &inputerSetData)
    {
    }
    sptr<IRemoteObject> AsObject()
    {
        return nullptr;
    }
};

auto g_service = PinAuthService::GetInstance();

void FuzzOnStart(Parcel &parcel)
{
    IAM_LOGI("begin");
    g_service->OnStart();
    IAM_LOGI("end");
}

void FuzzOnStop(Parcel &parcel)
{
    IAM_LOGI("begin");
    g_service->OnStop();
    IAM_LOGI("end");
}

void FuzzRegisterInputer(Parcel &parcel)
{
    IAM_LOGI("begin");
    sptr<InputerGetData> remoteInputer = nullptr;
    if (parcel.ReadBool()) {
        remoteInputer = new (std::nothrow) DummyRemoteInputer();
    }
    g_service->RegisterInputer(remoteInputer);
    IAM_LOGI("end");
}

void FuzzUnRegisterInputer(Parcel &parcel)
{
    IAM_LOGI("begin");
    g_service->UnRegisterInputer();
    IAM_LOGI("end");
}

void FuzzCheckPermission(Parcel &parcel)
{
    IAM_LOGI("begin");
    string permission;
    FillFuzzString(parcel, permission);
    g_service->CheckPermission(permission);
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FuzzOnStart);
FuzzFunc *g_fuzzFuncs[] = {FuzzOnStart, FuzzOnStop, FuzzRegisterInputer, FuzzUnRegisterInputer, FuzzCheckPermission};

void PinAuthServiceFuzzTest(const uint8_t *data, size_t size)
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
    OHOS::UserIam::PinAuth::PinAuthServiceFuzzTest(data, size);
    return 0;
}
