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
#include <uv.h>
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

static void GetPropertyInfoCallback(uv_work_t* work, int status)
{
    InputerHolder *inputerHolder = reinterpret_cast<InputerHolder *>(work->data);
    if (inputerHolder == nullptr) {
        HILOG_ERROR("inputerHolder is null");
        delete work;
        return;
    }
    napi_value inputerDataVarCtor;
    napi_status napiStatus = napi_new_instance(inputerHolder->env,
        GetCtorIInputerData(inputerHolder->env, inputerHolder->inputerData), 0, nullptr, &inputerDataVarCtor);
    if (napiStatus != napi_ok) {
        HILOG_ERROR("napi_new_instance faild");
        goto EXIT;
    }
    napi_value undefined;
    napiStatus = napi_get_undefined(inputerHolder->env, &undefined);
    if (napiStatus != napi_ok) {
        HILOG_ERROR("napi_get_undefined faild");
        goto EXIT;
    }
    napi_value return_val;
    napi_value type;
    napiStatus = napi_create_int32(inputerHolder->env, inputerHolder->authSubType, &type);
    if (napiStatus != napi_ok) {
        HILOG_ERROR("napi_create_int32 faild");
        goto EXIT;
    }
    napi_value argv [PIN_PARAMS_TWO];
    napi_value callbackRef;
    napiStatus = napi_get_reference_value(inputerHolder->env, inputerHolder->inputer, &callbackRef);
    if (napiStatus != napi_ok) {
        HILOG_ERROR("napi_get_reference_value faild");
        goto EXIT;
    }
    argv [PIN_PARAMS_ZERO] = type;
    argv [PIN_PARAMS_ONE] = inputerDataVarCtor;
    napiStatus = napi_call_function(inputerHolder->env, undefined, callbackRef, PIN_PARAMS_TWO, &argv[0], &return_val);
    if (napiStatus != napi_ok) {
        HILOG_ERROR("napi_call_function faild");
        goto EXIT;
    }
EXIT:
    delete inputerHolder;
    delete work;
}

void InputerImpl::OnGetData(int32_t authSubType, std::shared_ptr<OHOS::UserIAM::PinAuth::IInputerData> inputerData)
{
    uv_loop_s *loop(nullptr);
    napi_get_uv_event_loop(env_, &loop);
    if (loop == nullptr) {
        HILOG_ERROR("loop is null");
        return;
    }
    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        HILOG_ERROR("work is null");
        return;
    }
    InputerHolder *inputerHolder = new (std::nothrow) InputerHolder();
    if (inputerHolder == nullptr) {
        HILOG_ERROR("inputerHolder is null");
        delete work;
        return;
    }
    inputerHolder->env = env_;
    inputerHolder->inputer = inputer_;
    inputerHolder->authSubType = authSubType;
    inputerHolder->inputerData = inputerData;
    work->data = reinterpret_cast<void *>(inputerHolder);
    uv_queue_work(loop, work, [] (uv_work_t *work) { }, GetPropertyInfoCallback);
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
