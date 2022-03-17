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

#include "pin_auth_helper.h"
#include "pin_auth_impl.h"
#include "pin_auth_common.h"
#include "pinauth_log_wrapper.h"

using namespace OHOS::UserIAM::PinAuth;
namespace OHOS {
namespace PinAuth {
struct InputConstructorInfo {
    napi_value inputer;
    napi_async_work asyncWork;
    napi_ref onResult;
};

napi_value PinAuthServiceConstructor(napi_env env, napi_callback_info info)
{
    PINAUTH_HILOGI(MODULE_JS_NAPI, "PinAuthHelper, PinAuthServiceConstructor start");
    PinAuthImpl *pinAuthPtr = new (std::nothrow) PinAuthImpl();
    if (pinAuthPtr == nullptr) {
        PINAUTH_HILOGE(MODULE_JS_NAPI, "%{public}s, get nullptr", __func__);
        return nullptr;
    }
    napi_value thisVar = nullptr;
    size_t argc = PIN_PARAMS_ONE;
    napi_value argv[PIN_PARAMS_ONE] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));
    NAPI_CALL(env, napi_wrap(
        env, thisVar, pinAuthPtr,
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
    PINAUTH_HILOGI(MODULE_JS_NAPI, "PinAuthHelper, RegisterInputer start");
    napi_value thisVar = nullptr;
    size_t argcAsync = PIN_PARAMS_ONE;
    napi_value args[PIN_PARAMS_ONE] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, &thisVar, nullptr));
    napi_value result;
    NAPI_CALL(env, napi_get_boolean(env, false, &result));
    PinAuthImpl *pinAuthImpl = nullptr;
    NAPI_CALL(env, napi_unwrap(env, thisVar, (void **)&pinAuthImpl));
    if (pinAuthImpl == nullptr) {
        PINAUTH_HILOGE(MODULE_JS_NAPI, "PinAuthHelper, RegisterInputer pinauthimpl error");
        return result;
    }
    if (argcAsync == PIN_PARAMS_ONE) {
        napi_valuetype valuetype = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, args[PIN_PARAMS_ZERO], &valuetype));
        napi_value onGetData = nullptr;
        if (valuetype == napi_object) {
            PINAUTH_HILOGI(MODULE_JS_NAPI, "PinAuthHelper, RegisterInputer is an object");
            NAPI_CALL(env, napi_get_named_property(env, args[PIN_PARAMS_ZERO], "onGetData", &onGetData));
            if (onGetData == nullptr) {
                PINAUTH_HILOGE(MODULE_JS_NAPI, "PinAuthHelper, RegisterInputer napi_get_named_property error");
                return result;
            }
        } else if (valuetype == napi_function) {
            PINAUTH_HILOGI(MODULE_JS_NAPI, "PinAuthHelper, RegisterInputer is a function");
            onGetData = args[PIN_PARAMS_ZERO];
            if (onGetData == nullptr) {
                PINAUTH_HILOGE(MODULE_JS_NAPI, "PinAuthHelper, RegisterInputer getfunction error");
                return result;
            }
        } else {
            PINAUTH_HILOGE(MODULE_JS_NAPI, "PinAuthHelper, RegisterInputer param type error");
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
    PINAUTH_HILOGI(MODULE_JS_NAPI, "PinAuthHelper, UnregisterInputer start");
    napi_value thisVar = nullptr;
    napi_value result = nullptr;
    size_t argcAsync = PIN_PARAMS_ONE;
    napi_value args[PIN_PARAMS_ONE] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, &thisVar, nullptr));
    PinAuthImpl *pinAuthImpl = nullptr;
    NAPI_CALL(env, napi_unwrap(env, thisVar, (void **)&pinAuthImpl));
    if (pinAuthImpl == nullptr) {
        PINAUTH_HILOGE(MODULE_JS_NAPI, "PinAuthHelper, UnregisterInputer pinauthimpl error");
        return nullptr;
    }
    PINAUTH_HILOGI(MODULE_JS_NAPI, "PinAuthHelper, UnregisterInputer end");
    pinAuthImpl->UnregisterInputer(env);
    NAPI_CALL(env, napi_get_null(env, &result));
    return result;
}

napi_value Init(napi_env env, napi_value exports)
{
    napi_status status;
    status = napi_set_named_property(env, exports, "PINAuth", GetCtor(env));
    if (status != napi_ok) {
        PINAUTH_HILOGE(MODULE_JS_NAPI, "napi_set_named_property failed");
    }
    return exports;
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

napi_value AuthSubTypeConstructor(napi_env env)
{
    napi_value authSubType = nullptr;
    napi_value pinSix = nullptr;
    napi_value pinNumber = nullptr;
    napi_value pinMixed = nullptr;
    napi_value face2d = nullptr;
    napi_value face3d = nullptr;

    NAPI_CALL(env, napi_create_object(env, &authSubType));
    NAPI_CALL(env, napi_create_int32(env, (int32_t)AuthSubType::PIN_SIX, &pinSix));
    NAPI_CALL(env, napi_create_int32(env, (int32_t)AuthSubType::PIN_NUMBER, &pinNumber));
    NAPI_CALL(env, napi_create_int32(env, (int32_t)AuthSubType::PIN_MIXED, &pinMixed));
    NAPI_CALL(env, napi_create_int32(env, (int32_t)AuthSubType::FACE_2D, &face2d));
    NAPI_CALL(env, napi_create_int32(env, (int32_t)AuthSubType::FACE_3D, &face3d));
    NAPI_CALL(env, napi_set_named_property(env, authSubType, "PIN_SIX", pinSix));
    NAPI_CALL(env, napi_set_named_property(env, authSubType, "PIN_NUMBER", pinNumber));
    NAPI_CALL(env, napi_set_named_property(env, authSubType, "PIN_MIXED", pinMixed));
    NAPI_CALL(env, napi_set_named_property(env, authSubType, "FACE_2D", face2d));
    NAPI_CALL(env, napi_set_named_property(env, authSubType, "FACE_3D", face3d));
    return authSubType;
}

napi_value EnumExport(napi_env env, napi_value exports)
{
    napi_property_descriptor descriptors[] = {
        DECLARE_NAPI_PROPERTY("AuthSubType", AuthSubTypeConstructor(env)),
    };
    napi_define_properties(env, exports, sizeof(descriptors) / sizeof(*descriptors), descriptors);
    return exports;
}

static napi_value ModuleInit(napi_env env, napi_value exports)
{
    napi_value val = Init(env, exports);
    val = EnumExport(env, val);
    return val;
}
extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module module = {
        .nm_version = 1, // NAPI v1
        .nm_flags = 0,                     // normal
        .nm_filename = nullptr,
        .nm_register_func = ModuleInit,
        .nm_modname = "pinAuth",
        .nm_priv = nullptr,
        .reserved = {}
    };
    napi_module_register(&module);
}
} // namespace PinAuth
} // namespace OHOS