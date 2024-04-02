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

#ifndef PIN_AUTH_INTERFACE_ADAPTER
#define PIN_AUTH_INTERFACE_ADAPTER

#include "v2_0/ipin_auth_interface.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
using namespace OHOS::HDI::PinAuth::V2_0;
using IPinAuthInterface = OHOS::HDI::PinAuth::V2_0::IPinAuthInterface;
class PinAuthInterfaceAdapter {
public:
    explicit PinAuthInterfaceAdapter() = default;
    virtual ~PinAuthInterfaceAdapter() = default;

    virtual sptr<IPinAuthInterface> Get();
};
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS

#endif // PIN_AUTH_INTERFACE_ADAPTER