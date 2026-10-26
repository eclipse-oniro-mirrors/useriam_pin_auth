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

#include "napi/native_api.h"
#include "napi/native_common.h"

#include "iam_check.h"
#include "iam_logger.h"

#undef LOG_TAG
#define LOG_TAG "PIN_AUTH_NAPI"

namespace OHOS {
namespace UserIam {
namespace PinAuth {

static napi_value SetPinValidityPeriod(napi_env env, napi_callback_info info)
{
    return nullptr;
}

static napi_value GetPinValidityPeriod(napi_env env, napi_callback_info info)
{
    return nullptr;
}

static napi_value SetPinDeletionDisabledState(napi_env env, napi_callback_info info)
{
    return nullptr;
}

static napi_value GetPinDeletionDisabledState(napi_env env, napi_callback_info info)
{
    return nullptr;
}

static napi_value SetPinComplexityPolicy(napi_env env, napi_callback_info info)
{
    return nullptr;
}

static napi_value GetPinComplexityPolicy(napi_env env, napi_callback_info info)
{
    return nullptr;
}

static napi_value PinAuthNapiInit(napi_env env, napi_value exports)
{
    IAM_LOGI("start");
    napi_status status;
    napi_property_descriptor exportFuncs[] = {
        DECLARE_NAPI_FUNCTION("setPinValidityPeriod", SetPinValidityPeriod),
        DECLARE_NAPI_FUNCTION("getPinValidityPeriod", GetPinValidityPeriod),
        DECLARE_NAPI_FUNCTION("setPinDeletionDisabledState", SetPinDeletionDisabledState),
        DECLARE_NAPI_FUNCTION("getPinDeletionDisabledState", GetPinDeletionDisabledState),
        DECLARE_NAPI_FUNCTION("setPinComplexityPolicy", SetPinComplexityPolicy),
        DECLARE_NAPI_FUNCTION("getPinComplexityPolicy", GetPinComplexityPolicy),
    };
    status = napi_define_properties(env, exports,
        sizeof(exportFuncs) / sizeof(napi_property_descriptor), exportFuncs);
    IF_FALSE_LOGE_AND_RETURN_VAL(status == napi_ok, nullptr);
    IAM_LOGI("end");
    return exports;
}

} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS

napi_value ModuleInit(napi_env env, napi_value exports)
{
    return OHOS::UserIam::PinAuth::PinAuthNapiInit(env, exports);
}

extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module module = {
        .nm_version = 1,
        .nm_flags = 0,
        .nm_filename = nullptr,
        .nm_register_func = ModuleInit,
        .nm_modname = "userIAM.pinAuth",
        .nm_priv = nullptr,
        .reserved = {}
    };
    napi_module_register(&module);
}
