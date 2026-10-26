/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "ohos.userIAM.pinAuth.pinAuth.impl.hpp"

#include <cinttypes>
#include <string>
#include <utility>

#include "taihe/runtime.hpp"

using namespace taihe;
namespace pinAuth = ohos::userIAM::pinAuth::pinAuth;

void SetPinValidityPeriod(int32_t userId, int64_t validityPeriod)
{
    return;
}

optional<int64_t> GetPinValidityPeriod(int32_t userId)
{
    return {};
}

void SetPinDeletionDisabledState(int32_t userId, bool isDisabled)
{
    return;
}

optional<bool> GetPinDeletionDisabledState(int32_t userId)
{
    return {};
}

void SetPinComplexityPolicy(int32_t userId, const pinAuth::PinComplexityPolicy &policy)
{
    return;
}

optional<pinAuth::PinComplexityPolicy> GetPinComplexityPolicy(int32_t userId)
{
    return {};
}

TH_EXPORT_CPP_API_setPinValidityPeriod(SetPinValidityPeriod);
TH_EXPORT_CPP_API_getPinValidityPeriod(GetPinValidityPeriod);
TH_EXPORT_CPP_API_setPinDeletionDisabledState(SetPinDeletionDisabledState);
TH_EXPORT_CPP_API_getPinDeletionDisabledState(GetPinDeletionDisabledState);
TH_EXPORT_CPP_API_setPinComplexityPolicy(SetPinComplexityPolicy);
TH_EXPORT_CPP_API_getPinComplexityPolicy(GetPinComplexityPolicy);
