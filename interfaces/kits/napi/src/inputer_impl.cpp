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

#include "inputer_impl.h"
#include "pin_auth_common.h"
#include "pin_hilog_wrapper.h"
#include "securec.h"

namespace OHOS {
namespace PinAuth {
InputerImpl::InputerImpl(napi_env env, napi_ref inputer)
{
    env_ = env;
    inputer_ = inputer;
}

InputerImpl::~InputerImpl()
{
}
void InputerImpl::OnGetData(int32_t authSubType, std::shared_ptr<OHOS::UserIAM::PinAuth::IInputerData> inputerData)
{
    napi_status status;
    napi_value inputerDataVarCtor;
    status = napi_new_instance(env_, GetCtorIInputerData(env_,inputerData), 0, nullptr, &inputerDataVarCtor);
    if (status != napi_ok) {
        HILOG_ERROR("napi_new_instance faild");
    }
    napi_value undefined = 0;
    status = napi_get_undefined(env_, &undefined);
    if (status != napi_ok) {
        HILOG_ERROR("napi_get_undefined faild");
    }
    napi_value return_val;
    napi_value type;
    status = napi_create_int32(env_, authSubType, &type);
    if (status != napi_ok) {
        HILOG_ERROR("napi_create_int32 faild");
    }
    size_t argc = PIN_PARAMS_TWO;
    napi_value argv [PIN_PARAMS_TWO];
    napi_value callbackRef;
    status = napi_get_reference_value(env_, inputer_, &callbackRef);
    if (status != napi_ok) {
        HILOG_ERROR("napi_get_reference_value faild");
    }
    argv [0] = type;
    argv [1] = inputerDataVarCtor;
    status = napi_call_function(env_, undefined, callbackRef, argc, &argv[0], &return_val);
    if (status != napi_ok) {
        HILOG_ERROR("napi_call_function faild");
    }
}

napi_value GetCtorIInputerData(napi_env env, std::shared_ptr<OHOS::UserIAM::PinAuth::IInputerData> inputerData)
{
    if (inputerData != nullptr) {
        HILOG_INFO("GetCtorIInputerData inputerData not nullptr");
    }
    napi_property_descriptor clzDes[] = {
        DECLARE_NAPI_FUNCTION("onSetData", OHOS::PinAuth::OnSetData),
    };
    napi_value cons;
    NAPI_CALL(env, napi_define_class(env, "InputerData", NAPI_AUTO_LENGTH,
              InputDataConstructor, (void*)inputerData.get(),
        sizeof(clzDes) / sizeof(napi_property_descriptor), clzDes, &cons));
    return cons;
}

napi_value OnSetData(napi_env env, napi_callback_info info)
{
    size_t argcAsync = PIN_PARAMS_TWO;
    napi_value thisVar;
    napi_value result_ = nullptr;
    napi_value args[PIN_PARAMS_TWO] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, &thisVar, nullptr));
    OHOS::UserIAM::PinAuth::IInputerData *inputerData = nullptr;
    NAPI_CALL(env, napi_unwrap(env, thisVar, (void **)&inputerData));
    if (inputerData == nullptr) {
        return nullptr;
    }
    if (argcAsync == PIN_PARAMS_TWO) {
        napi_valuetype valuetype = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, args[PIN_PARAMS_ZERO], &valuetype));
        int32_t authSubType = VALID_AUTH_SUB_TYPE;
        if (valuetype == napi_number) {
            NAPI_CALL(env, napi_get_value_int32(env, args[PIN_PARAMS_ZERO], &authSubType));
            if (authSubType == VALID_AUTH_SUB_TYPE) {
                HILOG_ERROR("InputerImpl, OnSetData get authsubtype error");
                return nullptr;
            }
        }
        napi_typedarray_type arraytype;
        size_t length = 0;
        napi_value buffer = nullptr;
        size_t offset = 0;
        uint8_t *data = nullptr;
        bool isTypedArray = false;
        napi_is_typedarray(env, args[PIN_PARAMS_ONE], &isTypedArray);
        if (isTypedArray) {
            HILOG_INFO("args[PIN_PARAMS_ONE]  is a array");
        } else {
            HILOG_INFO("args[PIN_PARAMS_ONE]  is not a uint8array");
        }
        napi_get_typedarray_info(env, args[PIN_PARAMS_ONE], &arraytype, &length,
                                 reinterpret_cast<void **>(&data), &buffer, &offset);
        if (arraytype == napi_uint8_array) {
            HILOG_INFO("InputerImpl, OnSetData get uint8 array ");
        } else {
            HILOG_ERROR("InputerImpl, OnSetData get uint8 array error");
            return nullptr;
        }
        if (offset != 0) {
            HILOG_INFO(" offset is %{public}d", offset);
        } else {
        std::vector<uint8_t> result(data, data+length);
        inputerData->OnSetData(authSubType, result);
        }
    }
    NAPI_CALL(env, napi_get_null(env, &result_));
    return result_;
}

napi_value InputDataConstructor(napi_env env, napi_callback_info info)
{
    HILOG_INFO("InputerImpl, InputDataConstructor start");
    napi_value thisVar;
    void *data;
    size_t argcAsync = PIN_PARAMS_ONE;
    napi_value args[PIN_PARAMS_ONE] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, &thisVar, &data));
    OHOS::UserIAM::PinAuth::IInputerData *inputerData = static_cast<OHOS::UserIAM::PinAuth::IInputerData *>(data);
    if (thisVar == nullptr) {
        HILOG_ERROR("InputDataConstructor thisVar is nullptr");
    }
    if (inputerData == nullptr) {
        HILOG_ERROR("InputDataConstructor inputerData is nullptr");
    }
    NAPI_CALL(env, napi_wrap(
        env,
        thisVar,
        inputerData,
        [](napi_env env, void *data, void *hint) {
            OHOS::UserIAM::PinAuth::IInputerData *inputData =
            static_cast<OHOS::UserIAM::PinAuth::IInputerData*>(data);
            if (inputData != nullptr) {
                delete inputData;
            }
        },
        nullptr, nullptr));
    HILOG_INFO("InputerImpl, InputDataConstructor end");
    return thisVar;
}
} // namespace PinAuth
} // namespace OHOS