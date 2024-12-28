/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef PIN_AUTH_HDI
#define PIN_AUTH_HDI

#include "v2_1/pin_auth_types.h"
#include "v2_1/iexecutor_callback.h"
#include "v2_1/pin_auth_types.h"
#include "v2_1/iall_in_one_executor.h"
#include "v2_1/icollector.h"
#include "v2_1/iexecutor_callback.h"
#include "v2_1/ipin_auth_interface.h"
#include "v2_1/iverifier.h"
#include "v2_1/pin_auth_interface_service.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
using IPinAuthInterface = OHOS::HDI::PinAuth::V2_1::IPinAuthInterface;
using PinAuthInterfaceService = OHOS::HDI::PinAuth::V2_1::PinAuthInterfaceService;

using IAllInOneExecutor = OHOS::HDI::PinAuth::V2_1::IAllInOneExecutor;
using ICollector = OHOS::HDI::PinAuth::V2_1::ICollector;
using IVerifier = OHOS::HDI::PinAuth::V2_1::IVerifier;

using IExecutorCallback = OHOS::HDI::PinAuth::V2_1::IExecutorCallback;

using AuthType = OHOS::HDI::PinAuth::V2_1::AuthType;
using ExecutorRole = OHOS::HDI::PinAuth::V2_1::ExecutorRole;
using ExecutorSecureLevel = OHOS::HDI::PinAuth::V2_1::ExecutorSecureLevel;
using ExecutorInfo = OHOS::HDI::PinAuth::V2_1::ExecutorInfo;

using GetPropertyType = OHOS::HDI::PinAuth::V2_1::GetPropertyType;
using Property = OHOS::HDI::PinAuth::V2_1::Property;
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS

#endif // PIN_AUTH_HDI