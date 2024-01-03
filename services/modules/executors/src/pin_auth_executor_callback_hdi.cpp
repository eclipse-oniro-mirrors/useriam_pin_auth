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

#include "pin_auth_executor_callback_hdi.h"

#include <cinttypes>
#include <hdf_base.h>

#ifdef SENSORS_MISCDEVICE_ENABLE
#include "vibrator_agent.h"
#endif

#include "iam_logger.h"
#include "iam_common_defines.h"
#include "i_inputer_data_impl.h"
#include "inputer_get_data_proxy.h"
#include "pin_auth_hdi.h"

#define LOG_LABEL UserIam::Common::LABEL_PIN_AUTH_SA

namespace OHOS {
namespace UserIam {
namespace PinAuth {

PinAuthExecutorCallbackHdi::PinAuthExecutorCallbackHdi(std::shared_ptr<UserIam::UserAuth::IExecuteCallback>
    frameworkCallback, std::shared_ptr<PinAuthExecutorHdi> pinAuthExecutorHdi, uint32_t tokenId, bool isEnroll)
    : frameworkCallback_(frameworkCallback), pinAuthExecutorHdi_(pinAuthExecutorHdi),
      tokenId_(tokenId), isEnroll_(isEnroll) {}

#ifdef SENSORS_MISCDEVICE_ENABLE
void PinAuthExecutorCallbackHdi::DoVibrator()
{
    IAM_LOGI("begin");
    static const char *pinAuthEffect = "haptic.fail";
    bool pinEffectState = false;
    int32_t ret = Sensors::IsSupportEffect(pinAuthEffect, &pinEffectState);
    if (ret != 0) {
        IAM_LOGE("call IsSupportEffect fail %{public}d", ret);
        return;
    }
    if (!pinEffectState) {
        IAM_LOGE("effect not support");
        return;
    }
    if (!Sensors::SetUsage(USAGE_PHYSICAL_FEEDBACK)) {
        IAM_LOGE("call SetUsage fail");
        return;
    }
    ret = Sensors::StartVibrator(pinAuthEffect);
    if (ret != 0) {
        IAM_LOGE("call StartVibrator fail %{public}d", ret);
        return;
    }
    IAM_LOGI("end");
}
#endif

int32_t PinAuthExecutorCallbackHdi::OnResult(int32_t code, const std::vector<uint8_t>& extraInfo)
{
    IAM_LOGI("OnResult %{public}d", code);
    UserAuth::ResultCode retCode = ConvertResultCode(code);
#ifdef SENSORS_MISCDEVICE_ENABLE
    if ((!isEnroll_) && (retCode == UserAuth::FAIL)) {
        DoVibrator();
    }
#else
    IAM_LOGE("vibrator not support");
#endif
    frameworkCallback_->OnResult(retCode, extraInfo);
    return HDF_SUCCESS;
}

int32_t PinAuthExecutorCallbackHdi::OnGetData(uint64_t scheduleId, const std::vector<uint8_t> &salt,
    uint64_t authSubType)
{
    IAM_LOGI("Start tokenId_ is %{public}u", tokenId_);
    if (OnGetDataV1_1(scheduleId, salt, authSubType, 0) != HDF_SUCCESS) {
        IAM_LOGE("invoke OnGetDataV1_1 fail");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t PinAuthExecutorCallbackHdi::OnGetDataV1_1(uint64_t scheduleId, const std::vector<uint8_t> &algoParameter,
    uint64_t authSubType, uint32_t algoVersion)
{
    IAM_LOGI("Start tokenId_ is %{public}u", tokenId_);
    sptr<InputerGetData> inputer = PinAuthManager::GetInstance().GetInputerLock(tokenId_);
    if (inputer == nullptr) {
        IAM_LOGE("inputer is nullptr");
        return HDF_FAILURE;
    }
    sptr<IInputerDataImpl> iInputerDataImpl(new (std::nothrow) IInputerDataImpl(scheduleId, pinAuthExecutorHdi_));
    if (iInputerDataImpl == nullptr) {
        IAM_LOGE("iInputerDataImpl is nullptr");
    }

    inputer->OnGetData(authSubType, algoParameter, iInputerDataImpl, algoVersion, isEnroll_);
    return HDF_SUCCESS;
}

UserAuth::ResultCode PinAuthExecutorCallbackHdi::ConvertResultCode(const int32_t in)
{
    UserAuth::ResultCode hdiIn = static_cast<UserAuth::ResultCode>(in);
    if (hdiIn < UserAuth::ResultCode::SUCCESS || hdiIn > UserAuth::ResultCode::LOCKED) {
        IAM_LOGE("convert hdi undefined result code %{public}d to framework result code GENERAL_ERROR", hdiIn);
        return UserAuth::ResultCode::GENERAL_ERROR;
    }

    IAM_LOGI("covert hdi result code %{public}d to framework result code", hdiIn);
    return hdiIn;
}
} // PinAuth
} // UserIam
} // OHOS