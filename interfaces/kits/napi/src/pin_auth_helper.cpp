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

#include "iam_logger.h"

#include "pin_auth_impl.h"
#include "pin_auth_common.h"

#define LOG_LABEL UserIAM::Common::LABEL_PIN_AUTH_NAPI

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
    IAM_LOGI("start");
    PinAuthImpl *pinAuthPtr = new (std::nothrow) PinAuthImpl();
    if (pinAuthPtr == nullptr) {
        IAM_LOGE("pinAuthPtr is nullptr");
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
    IAM_LOGI("start");
    napi_value thisVar = nullptr;
    size_t argcAsync = PIN_PARAMS_ONE;
    napi_value args[PIN_PARAMS_ONE] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, &thisVar, nullptr));
    napi_value result;
    NAPI_CALL(env, napi_get_boolean(env, false, &result));
    PinAuthImpl *pinAuthImpl = nullptr;
    NAPI_CALL(env, napi_unwrap(env, thisVar, (void **)&pinAuthImpl));
    if (pinAuthImpl == nullptr) {
        IAM_LOGE("pinAuthImpl is nullptr");
        return result;
    }
    if (argcAsync == PIN_PARAMS_ONE) {
        napi_valuetype valuetype = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, args[PIN_PARAMS_ZERO], &valuetype));
        napi_value onGetData = nullptr;
        if (valuetype == napi_object) {
            IAM_LOGI("param type is an object");
            NAPI_CALL(env, napi_get_named_property(env, args[PIN_PARAMS_ZERO], "onGetData", &onGetData));
            if (onGetData == nullptr) {
                IAM_LOGE("onGetData is nullptr");
                return result;
            }
        } else if (valuetype == napi_function) {
            IAM_LOGI("param type is a function");
            onGetData = args[PIN_PARAMS_ZERO];
            if (onGetData == nullptr) {
                IAM_LOGE("getfunction error");
                return result;
            }
        } else {
            IAM_LOGE("param type error");
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
    IAM_LOGI("start");
    napi_value thisVar = nullptr;
    napi_value result = nullptr;
    size_t argcAsync = PIN_PARAMS_ONE;
    napi_value args[PIN_PARAMS_ONE] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, &thisVar, nullptr));
    PinAuthImpl *pinAuthImpl = nullptr;
    NAPI_CALL(env, napi_unwrap(env, thisVar, (void **)&pinAuthImpl));
    if (pinAuthImpl == nullptr) {
        IAM_LOGE("pinAuthImpl is nullptr");
        return nullptr;
    }
    pinAuthImpl->UnregisterInputer(env);
    NAPI_CALL(env, napi_get_null(env, &result));
    IAM_LOGI("end");
    return result;
}

napi_value Init(napi_env env, napi_value exports)
{
    IAM_LOGI("start");
    napi_status status = napi_set_named_property(env, exports, "PINAuth", GetCtor(env));
    if (status != napi_ok) {
        IAM_LOGE("napi_set_named_property failed");
    }
    return exports;
}

napi_value GetCtor(napi_env env)
{
    IAM_LOGI("start");
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
    IAM_LOGI("start");
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
    IAM_LOGI("start");
    napi_property_descriptor descriptors[] = {
        DECLARE_NAPI_PROPERTY("AuthSubType", AuthSubTypeConstructor(env)),
    };
    napi_define_properties(env, exports, sizeof(descriptors) / sizeof(*descriptors), descriptors);
    return exports;
}

static napi_value ModuleInit(napi_env env, napi_value exports)
{
    IAM_LOGI("start");
    napi_value val = Init(env, exports);
    val = EnumExport(env, val);
    return val;
}
extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module module = {
        .nm_version = 1,
        .nm_flags = 0,
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