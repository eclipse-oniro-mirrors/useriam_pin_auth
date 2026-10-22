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

/**
 * @file pinauth_callback.h
 *
 * @brief The definition of pinAuth's callback.
 * @since 7.1
 * @version 1.0
 */

#ifndef PINAUTH_CALLBACK_H
#define PINAUTH_CALLBACK_H

#include <memory>
#include <vector>
#include "nocopyable.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
class AuthFailureCountListener {
public:
    virtual ~AuthFailureCountListener() = default;

    /**
    * @brief Notify the cumulative authentication fail count change
    *
    * Called immediately after registration with the current fail count,
    * and called again whenever the fail count for the specified userId changes.
    *
    * @param userId The id of the user to listen on.
    * @param failCount The cumulative authentication fail count after the change.
    */
    virtual void OnAuthFailureCountChanged(int32_t userId, int32_t failCount) = 0;
};
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS

#endif // PINAUTH_CALLBACK_H
