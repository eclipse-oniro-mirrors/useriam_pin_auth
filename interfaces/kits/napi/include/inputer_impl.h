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

#ifndef PINAUTH_INPUTERIMPL_H
#define PINAUTH_INPUTERIMPL_H

#include "i_inputer.h"
#include "i_inputer_data.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "pin_auth_common.h"

namespace OHOS {
namespace PinAuth {
const int VALID_AUTH_SUB_TYPE = -1;

napi_value OnSetData(napi_env env, napi_callback_info info);
napi_value InputDataConstructor(napi_env env, napi_callback_info info);
napi_value GetCtorIInputerData(napi_env env, std::shared_ptr<OHOS::UserIAM::PinAuth::IInputerData> inputerData);

class InputerImpl : public OHOS::UserIAM::PinAuth::IInputer {
public:
    InputerImpl(napi_env env, napi_ref inputer);
    virtual ~InputerImpl();
    napi_env env_;
    napi_ref inputer_;
    void OnGetData(int32_t authSubType, std::shared_ptr<OHOS::UserIAM::PinAuth::IInputerData> inputerData);
};

typedef struct InputerHolder {
    napi_env env;
    napi_ref inputer;
    int32_t authSubType;
    std::shared_ptr<OHOS::UserIAM::PinAuth::IInputerData> inputerData;
} InputerHolder;
} // namespace PinAuth
} // namespace OHOS


#endif // PINAUTH_INPUTERIMPL_H
