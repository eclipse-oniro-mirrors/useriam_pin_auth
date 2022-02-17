/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "pinauth_log_wrapper.h"
#include "pinauth_common_event_subscriber.h"
#include "coauth_info_define.h"

namespace OHOS {
namespace UserIAM {
namespace PinAuth {
PinAuthCommonEventSubscriber::PinAuthCommonEventSubscriber(
    const CommonEventSubscribeInfo &subscribeInfo, PinAuthService* callback)
    : CommonEventSubscriber(subscribeInfo), callback_(callback)
{
    PINAUTH_HILOGI(MODULE_SERVICE, "PinAuthCommonEventSubscriber enter");
}

void PinAuthCommonEventSubscriber::OnReceiveEvent(const CommonEventData &data)
{
    PINAUTH_HILOGI(MODULE_SERVICE, "OnReceiveEvent enter");
    OHOS::EventFwk::Want want = data.GetWant();
    std::string action = want.GetAction();
    PINAUTH_HILOGD(MODULE_SERVICE, "Recieved common event:%{public}s", action.c_str());
    if (action == REGISTER_NOTIFICATION) {
        callback_->ActuatorInfoQuery();
        return;
    }
}
} // namespace PinAuth
} // namespace UserIAM
}  // namespace OHOS