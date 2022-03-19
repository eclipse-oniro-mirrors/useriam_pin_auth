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

#ifndef FACE_RECOGNITION_PIN_AUTH_COMMON_H
#define FACE_RECOGNITION_PIN_AUTH_COMMON_H

#include "i_inputer.h"
#include "i_inputer_data.h"
#include "napi/native_api.h"
#include "napi/native_common.h"

namespace OHOS {
namespace PinAuth {
constexpr size_t PIN_PARAMS_ZERO = 0;
constexpr size_t PIN_PARAMS_ONE = 1;
constexpr size_t PIN_PARAMS_TWO = 2;
constexpr int OK = 0;
constexpr int FAIL = 1;
constexpr int REGISTER_CODE = 1;
enum class AuthSubType {

    /* Authentication sub type six number pin. */
    PIN_SIX = 10000,

    /* Authentication sub type self defined number pin. */
    PIN_NUMBER = 10001,

    /* Authentication sub type 2D face. */
    PIN_MIXED = 10002,

    /* Authentication sub type 2D face. */

    FACE_2D = 20000,

    /* Authentication sub type 3D face. */
    FACE_3D = 20001
};
} // namespace PinAuth
} // namespace OHOS
#endif // FACE_RECOGNITION_PIN_AUTH_COMMON_H
