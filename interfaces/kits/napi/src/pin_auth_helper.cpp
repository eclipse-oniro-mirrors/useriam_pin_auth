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

#include "pin_auth_helper.h"
#include "pin_auth_impl.h"
#include "pin_auth_common.h"
#include "pin_hilog_wrapper.h"

namespace OHOS {
namespace PinAuth {
struct InputConstructorInfo {
    napi_value inputer;
    napi_async_work asyncWork;
    napi_ref onResult;
};

napi_value PinAuthServiceConstructor(napi_env env, napi_callback_info info)
{
    HILOG_INFO("PinAuthHelper, PinAuthServiceConstructor start");
    std::shared_ptr<OHOS::PinAuth::PinAuthImpl> pinAuthPtr = std::make_shared<PinAuthImpl>();
    napi_value thisVar = nullptr;
    size_t argc = PIN_PARAMS_ONE;
    napi_value argv[PIN_PARAMS_ONE] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));
    NAPI_CALL(env, napi_wrap(
        env, thisVar, pinAuthPtr.get(),
        [](napi_env env, void *data, void *hint) {
            PinAuthImpl *pinAuthImpl = static_cast<PinAuthImpl *>(data);
            if (pinAuthImpl != nullptr) {
                delete pinAuthImpl;
            }
        },
        nullptr, nullptr));
    return thisVar;
}

napi_value RegisterInputer(napi_env env, napi_callback_info info)
{
    HILOG_INFO("PinAuthHelper, RegisterInputer start");
    napi_value thisVar = nullptr;
    size_t argcAsync = PIN_PARAMS_ONE;
    napi_value args[PIN_PARAMS_ONE] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, &thisVar, nullptr));
    napi_value result;
    NAPI_CALL(env, napi_get_boolean(env, false, &result));
    PinAuthImpl *pinAuthImpl = nullptr;
    NAPI_CALL(env, napi_unwrap(env, thisVar, (void **)&pinAuthImpl));
    if (pinAuthImpl == nullptr) {
        HILOG_ERROR("PinAuthHelper, RegisterInputer pinauthimpl error");
        return result;
    }
    if (argcAsync == PIN_PARAMS_ONE) {
        napi_valuetype valuetype = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, args[PIN_PARAMS_ZERO], &valuetype));
        napi_value onGetData = nullptr;
        if (valuetype == napi_object) {
            HILOG_INFO("PinAuthHelper, RegisterInputer is an object");
            NAPI_CALL(env, napi_get_named_property(env, args[PIN_PARAMS_ZERO], "onGetData", &onGetData));
            if (onGetData == nullptr) {
                HILOG_ERROR("PinAuthHelper, RegisterInputer napi_get_named_property error");
                return result;
            }
        } else if (valuetype == napi_function) {
            HILOG_INFO("PinAuthHelper, RegisterInputer is a function");
            onGetData = args[PIN_PARAMS_ZERO];
            if (onGetData == nullptr) {
                HILOG_ERROR("PinAuthHelper, RegisterInputer getfunction error");
                return result;
            }
        } else {
            HILOG_ERROR("PinAuthHelper, RegisterInputer param type error");
            return result;
        }
        napi_ref callbackRef;
        NAPI_CALL(env, napi_create_reference(env, onGetData, 1, &callbackRef));
        bool callResult = pinAuthImpl->RegisterInputer(env, callbackRef);
        NAPI_CALL(env, napi_get_boolean(env, callResult, &result));
    }
    return result;
}

napi_value UnregisterInputer(napi_env env, napi_callback_info info)
{
    HILOG_INFO("PinAuthHelper, UnregisterInputer start");
    napi_value thisVar = nullptr;
    napi_value result = nullptr;
    size_t argcAsync = PIN_PARAMS_ONE;
    napi_value args[PIN_PARAMS_ONE] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, &thisVar, nullptr));
    PinAuthImpl *pinAuthImpl = nullptr;
    NAPI_CALL(env, napi_unwrap(env, thisVar, (void **)&pinAuthImpl));
    if (pinAuthImpl == nullptr) {
        HILOG_ERROR("PinAuthHelper, UnregisterInputer pinauthimpl error");
        return nullptr;
    }
    HILOG_INFO("PinAuthHelper, UnregisterInputer end");
    pinAuthImpl->UnregisterInputer(env);
    NAPI_CALL(env, napi_get_null(env, &result));
    return result;
}

void Init(napi_env env, napi_value exports)
{
    napi_status status;
    napi_property_descriptor exportFuncs[] = {
        DECLARE_NAPI_FUNCTION("constructor", OHOS::PinAuth::Constructor),
    };
    status = napi_define_properties(env, exports, sizeof(exportFuncs) / sizeof(*exportFuncs), exportFuncs);
    if (status != napi_ok) {
        HILOG_ERROR("napi_define_properties faild");
    }
}

napi_value Constructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_new_instance(env, GetCtor(env), 0, nullptr, &thisVar));
    return thisVar;
}

napi_value GetCtor(napi_env env)
{
    napi_value cons = nullptr;
    napi_property_descriptor clzDes[] = {
        DECLARE_NAPI_FUNCTION("registerInputer", OHOS::PinAuth::RegisterInputer),
        DECLARE_NAPI_FUNCTION("unregisterInputer", OHOS::PinAuth::UnregisterInputer),
    };
    NAPI_CALL(env, napi_define_class(env, "PinAuth", NAPI_AUTO_LENGTH, PinAuthServiceConstructor, nullptr,
        sizeof(clzDes) / sizeof(napi_property_descriptor), clzDes, &cons));
    return cons;
}
} // namespace PinAuth
} // namespace OHOS