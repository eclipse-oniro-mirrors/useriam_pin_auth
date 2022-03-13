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

#include "pin_auth_impl.h"
#include "pin_auth_common.h"
#include "pinauth_register.h"
#include "inputer_impl.h"

namespace OHOS {
namespace PinAuth {
PinAuthImpl::PinAuthImpl()
{
}

PinAuthImpl::~PinAuthImpl()
{
}

bool PinAuthImpl::RegisterInputer(napi_env env, napi_ref inputer)
{
    std::shared_ptr<OHOS::UserIAM::PinAuth::IInputer> inputerSharePtr = std::make_shared<InputerImpl>(env, inputer);
    bool resultCode = UserIAM::PinAuth::PinAuthRegister::GetInstance().RegisterInputer(inputerSharePtr);
    return resultCode;
}


void PinAuthImpl::UnregisterInputer(napi_env env)
{
    UserIAM::PinAuth::PinAuthRegister::GetInstance().UnRegisterInputer();
}
} // namespace PinAuth
} // namespace OHOS