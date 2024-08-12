/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"
#include "iam_common_defines.h"
#include "i_inputer_data_impl.h"
#include "inputer_get_data_proxy.h"
#include "pin_auth_hdi.h"

#define LOG_TAG "PIN_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace PinAuth {

PinAuthExecutorCallbackHdi::PinAuthExecutorCallbackHdi(
    std::shared_ptr<UserIam::UserAuth::IExecuteCallback> frameworkCallback,
    std::shared_ptr<PinAuthAllInOneHdi> pinAuthAllInOneHdi, const UserAuth::ExecutorParam &param,
    GetDataMode mode)
    : frameworkCallback_(frameworkCallback), pinAuthAllInOneHdi_(pinAuthAllInOneHdi), pinAuthCollectorHdi_(nullptr),
      tokenId_(param.tokenId), mode_(mode), scheduleId_(param.scheduleId), authIntent_(param.authIntent) {}

PinAuthExecutorCallbackHdi::PinAuthExecutorCallbackHdi(
    std::shared_ptr<UserAuth::IExecuteCallback> frameworkCallback,
    std::shared_ptr<PinAuthCollectorHdi> pinAuthCollectorHdi, const UserAuth::ExecutorParam &param,
    GetDataMode mode)
    : frameworkCallback_(frameworkCallback), pinAuthAllInOneHdi_(nullptr), pinAuthCollectorHdi_(pinAuthCollectorHdi),
      tokenId_(param.tokenId), mode_(mode), scheduleId_(param.scheduleId), authIntent_(param.authIntent) {}

PinAuthExecutorCallbackHdi::PinAuthExecutorCallbackHdi(std::shared_ptr<UserAuth::IExecuteCallback> frameworkCallback,
    const UserAuth::ExecutorParam &param, GetDataMode mode)
    : frameworkCallback_(frameworkCallback), pinAuthAllInOneHdi_(nullptr), pinAuthCollectorHdi_(nullptr),
      tokenId_(param.tokenId), mode_(mode), scheduleId_(param.scheduleId), authIntent_(param.authIntent) {}

void PinAuthExecutorCallbackHdi::DoVibrator()
{
#ifdef SENSORS_MISCDEVICE_ENABLE
    IAM_LOGI("begin");
    static const char *pinAuthEffect = "haptic.notice.fail";
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
#else
    IAM_LOGE("vibrator not support");
#endif
}

int32_t PinAuthExecutorCallbackHdi::OnResult(int32_t code, const std::vector<uint8_t>& extraInfo)
{
    IAM_LOGI("OnResult %{public}d", code);

    UserAuth::ResultCode retCode = ConvertResultCode(code);
    if ((mode_ == GET_DATA_MODE_ALL_IN_ONE_PIN_AUTH) && (retCode == UserAuth::FAIL)) {
        if (authIntent_ != UserAuth::SILENT_AUTH) {
            DoVibrator();
        }
    }
    IF_FALSE_LOGE_AND_RETURN_VAL(frameworkCallback_ != nullptr, HDF_FAILURE);

    frameworkCallback_->OnResult(retCode, extraInfo);
    return HDF_SUCCESS;
}

int32_t PinAuthExecutorCallbackHdi::OnGetData(const std::vector<uint8_t>& algoParameter, uint64_t authSubType,
    uint32_t algoVersion, const std::vector<uint8_t>& challenge)
{
    IAM_LOGI("Start tokenId_ is %{public}s", GET_MASKED_STRING(tokenId_).c_str());
    sptr<InputerGetData> inputer = PinAuthManager::GetInstance().GetInputerLock(tokenId_);
    IF_FALSE_LOGE_AND_RETURN_VAL(inputer != nullptr, HDF_FAILURE);

    if (pinAuthAllInOneHdi_ != nullptr) {
        sptr<IInputerDataImpl> iInputerDataImpl(new (std::nothrow) IInputerDataImpl(scheduleId_, pinAuthAllInOneHdi_));
        IF_FALSE_LOGE_AND_RETURN_VAL(iInputerDataImpl != nullptr, HDF_FAILURE);

        InputerGetDataParam param = {
            .mode = mode_,
            .authSubType = authSubType,
            .algoVersion = algoVersion,
            .algoParameter = algoParameter,
            .challenge = challenge,
            .inputerSetData = iInputerDataImpl,
        };
        inputer->OnGetData(param);
        return HDF_SUCCESS;
    } else if (pinAuthCollectorHdi_ != nullptr) {
        sptr<IInputerDataImpl> iInputerDataImpl(new (std::nothrow) IInputerDataImpl(scheduleId_, pinAuthCollectorHdi_));
        IF_FALSE_LOGE_AND_RETURN_VAL(iInputerDataImpl != nullptr, HDF_FAILURE);

        InputerGetDataParam param = {
            .mode = mode_,
            .authSubType = authSubType,
            .algoVersion = algoVersion,
            .algoParameter = algoParameter,
            .challenge = challenge,
            .inputerSetData = iInputerDataImpl,
        };
        inputer->OnGetData(param);
        return HDF_SUCCESS;
    }
    return HDF_FAILURE;
}

int32_t PinAuthExecutorCallbackHdi::OnTip(int32_t tip, const std::vector<uint8_t>& extraInfo)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(frameworkCallback_ != nullptr, HDF_FAILURE);
    frameworkCallback_->OnAcquireInfo(tip, extraInfo);
    return HDF_SUCCESS;
}

int32_t PinAuthExecutorCallbackHdi::OnMessage(int32_t destRole, const std::vector<uint8_t>& msg)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(frameworkCallback_ != nullptr, HDF_FAILURE);
    frameworkCallback_->OnMessage(destRole, msg);
    return HDF_SUCCESS;
}

UserAuth::ResultCode PinAuthExecutorCallbackHdi::ConvertResultCode(const int32_t in)
{
    UserAuth::ResultCode hdiIn = static_cast<UserAuth::ResultCode>(in);
    if (hdiIn < UserAuth::ResultCode::SUCCESS || hdiIn > UserAuth::ResultCode::COMPLEXITY_CHECK_FAILED) {
        IAM_LOGE("convert hdi undefined result code %{public}d to framework result code GENERAL_ERROR", hdiIn);
        return UserAuth::ResultCode::GENERAL_ERROR;
    }

    IAM_LOGI("covert hdi result code %{public}d to framework result code", hdiIn);
    return hdiIn;
}

} // PinAuth
} // UserIam
} // OHOS