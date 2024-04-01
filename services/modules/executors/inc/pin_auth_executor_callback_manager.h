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

#ifndef PIN_AUTH_EXECUTOR_CALLBACK_MANAGER_H
#define PIN_AUTH_EXECUTOR_CALLBACK_MANAGER_H

#include <cstdint>
#include <mutex>
#include <unordered_map>

#include "iremote_object.h"
#include "refbase.h"
#include "singleton.h"

#include "pin_auth_executor_callback_hdi.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
class PinAuthExecutorCallbackManager : public DelayedRefSingleton<PinAuthExecutorCallbackManager> {
    DECLARE_DELAYED_REF_SINGLETON(PinAuthExecutorCallbackManager);
public:
    bool SetCallback(uint64_t scheduleId, const sptr<PinAuthExecutorCallbackHdi> &callback);
    void RemoveCallback(uint64_t scheduleId);
    sptr<PinAuthExecutorCallbackHdi> GetCallbackLock(uint64_t scheduleId);

private:
    std::unordered_map<uint64_t, sptr<PinAuthExecutorCallbackHdi>> pinAuthExecutorCallbackMap_;
    std::mutex mutex_;
};
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS

#endif // PIN_AUTH_EXECUTOR_CALLBACK_MANAGER_H
