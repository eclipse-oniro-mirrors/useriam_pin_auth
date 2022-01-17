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
#ifndef FACERECOGNITION_PIN_AUTH_H
#define FACERECOGNITION_PIN_AUTH_H

#include <vector>

#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "pin_auth_common.h"

#include "inputer_impl.h"

namespace OHOS {
namespace PinAuth {
class PinAuthImpl {
public:
    PinAuthImpl();
    ~PinAuthImpl();
    napi_value inputer;
    napi_value registerCode;
    InputerImpl *inputerSharePtrImpl;
    bool RegisterInputer(napi_env env, napi_ref inputer);
    void UnregisterInputer(napi_env env);
    napi_value OnSetData(napi_env env, int32_t authSubType, std::vector<uint32_t> data);
};
} // namespace PinAuth
} // namespace OHOS
#endif // FACERECOGNITION_PIN_AUTH_H
