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

#include "i_inputer_data_impl.h"

#include "co_auth_defines.h"

#include "pinauth_log_wrapper.h"
#include "pinauth_executor_hdi.h"

namespace OHOS {
namespace UserIAM {
namespace PinAuth {
using namespace OHOS::UserIam::UserAuth;
IInputerDataImpl::IInputerDataImpl(uint64_t scheduleId, std::shared_ptr<PinAuthExecutorHdi> hdi)
    : scheduleId_(scheduleId), hdi_(hdi) {}
IInputerDataImpl::~IInputerDataImpl() {}

void IInputerDataImpl::OnSetData(int32_t authSubType, std::vector<uint8_t> data)
{
    PINAUTH_HILOGI(MODULE_SERVICE, "start");
    std::lock_guard<std::mutex> guard(mutex_);
    if (hdi_->OnSetData(scheduleId_, authSubType, data) != SUCCESS) {
        PINAUTH_HILOGE(MODULE_SERVICE, "IInputerDataImpl::onSetData event has canceled");
        return;
    }

    PINAUTH_HILOGI(MODULE_SERVICE, "IInputerDataImpl::OnSetData end");
}
} // namespace PinAuth
} // namespace UserIAM
} // namespace OHOS
