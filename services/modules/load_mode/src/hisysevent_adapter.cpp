/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "hisysevent_adapter.h"

#include "hisysevent.h"
#include "iam_logger.h"
 
#define LOG_TAG "PIN_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
namespace {
    constexpr char STR_ERROR_CODE[] = "ERROR_CODE";
}

using HiSysEvent = OHOS::HiviewDFX::HiSysEvent;

void ReportSaLoadDriverFailure(const SaLoadDriverFailureTrace &info)
{
    int32_t ret = HiSysEventWrite(HiSysEvent::Domain::PIN_AUTH_SA, "SA_LOAD_DRIVER_FAILURE",
        HiSysEvent::EventType::FAULT,
        STR_ERROR_CODE, info.errCode);
    if (ret != 0) {
        IAM_LOGE("hisysevent write failed! ret %{public}d", ret);
    }
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS