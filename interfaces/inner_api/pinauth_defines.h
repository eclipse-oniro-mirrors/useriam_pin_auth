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
 * @file pinauth_defines.h
 *
 * @brief The definition of pinAuth's const .
 * @since 7.1
 * @version 1.0
 */

#ifndef PINAUTH_DEFINES_H
#define PINAUTH_DEFINES_H

namespace OHOS {
namespace UserIam {
namespace PinAuth {
enum PinAuthResult : int32_t {
    SUCCESS = 0,
    GENERAL_ERROR = 1,
};
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS

#endif // PINAUTH_DEFINES_H
