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

#ifndef PIN_AUTH_EXECUTOR_HDI_COMMON_H
#define PIN_AUTH_EXECUTOR_HDI_COMMON_H

#include "co_auth_client_defines.h"
#include "iam_executor_framework_types.h"
#include "pin_auth_hdi.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
UserAuth::ResultCode MoveHdiExecutorInfo(ExecutorInfo &in, UserAuth::ExecutorInfo &out);
void MoveHdiProperty(Property &in, UserAuth::Property &out);
UserAuth::ResultCode ConvertAuthType(AuthType in, UserAuth::AuthType &out);
UserAuth::ResultCode ConvertExecutorRole(ExecutorRole in, UserAuth::ExecutorRole &out);
UserAuth::ResultCode ConvertExecutorSecureLevel(ExecutorSecureLevel in, UserAuth::ExecutorSecureLevel &out);
UserAuth::ResultCode ConvertHdiResultCode(int32_t in);
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS

#endif // PIN_AUTH_EXECUTOR_HDI_COMMON_H