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

#ifndef PINAUTH_COMMON_EVENT_SUBSCRIBER_H
#define PINAUTH_COMMON_EVENT_SUBSCRIBER_H

#include "nocopyable.h"

#include "pinauth_service.h"
#include "common_event_subscriber.h"

namespace OHOS {
namespace UserIAM {
namespace PinAuth {
using CommonEventSubscriber = OHOS::EventFwk::CommonEventSubscriber;
using CommonEventData = OHOS::EventFwk::CommonEventData;
using CommonEventSubscribeInfo = OHOS::EventFwk::CommonEventSubscribeInfo;

class PinAuthCommonEventSubscriber : public CommonEventSubscriber {
public:
    DISALLOW_COPY_AND_MOVE(PinAuthCommonEventSubscriber);
    explicit PinAuthCommonEventSubscriber(
        const CommonEventSubscribeInfo &subscribeInfo, PinAuthService* callback);
    ~PinAuthCommonEventSubscriber() override = default;

    void OnReceiveEvent(const CommonEventData &data) override;

private:
    PinAuthService* callback_;
};
} // namespace PinAuth
} // namespace UserIAM
}  // namespace OHOS

#endif  // PINAUTH_COMMON_EVENT_SUBSCRIBER_H
