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

#include "pinauth_executor_callback_hdi.h"
#include <cinttypes>
#include <v1_0/executor_proxy.h>
#include <hdf_base.h>
#include "iam_logger.h"
#include "i_inputer_data_impl.h"
#include "pinauth_defines.h"
#include "v1_0/pin_auth_types.h"

#define LOG_LABEL UserIAM::Common::LABEL_PIN_AUTH_SA

namespace OHOS {
namespace UserIam {
namespace PinAuth {
PinAuthExecutorCallbackHdi::PinAuthExecutorCallbackHdi(std::shared_ptr<UserIam::UserAuth::IExecuteCallback>
    frameworkCallback, std::shared_ptr<PinAuthExecutorHdi> pinAuthExecutorHdi, uint32_t tokenId)
    : frameworkCallback_(frameworkCallback), pinAuthExecutorHdi_(pinAuthExecutorHdi), tokenId_(tokenId) {}

int32_t PinAuthExecutorCallbackHdi::OnResult(int32_t code, const std::vector<uint8_t>& extraInfo)
{
    IAM_LOGI("OnResult %{public}d", code);
    UserIam::UserAuth::ResultCode retCode = ConvertResultCode(code);
    frameworkCallback_->OnResult(retCode, extraInfo);
    return HDF_SUCCESS;
}

int32_t PinAuthExecutorCallbackHdi::OnGetData(uint64_t scheduleId, const std::vector<uint8_t>& salt,
    uint64_t authSubType)
{
    IAM_LOGI("Start tokenId_ is %{public}u", tokenId_);
    sptr<IRemoteInputer> inputer = PinAuthManager::GetInstance().getInputerLock(tokenId_);
    if (inputer == nullptr) {
        IAM_LOGE("inputer is nullptr");
        return HDF_FAILURE;
    }
    sptr<IInputerDataImpl> iInputerDataImpl = new (std::nothrow) IInputerDataImpl(scheduleId, pinAuthExecutorHdi_);
    if (iInputerDataImpl == nullptr) {
        IAM_LOGE("iInputerDataImpl is nullptr");
    }
    inputer->OnGetData(authSubType, salt, iInputerDataImpl);
    return HDF_SUCCESS;
}

UserIam::UserAuth::ResultCode PinAuthExecutorCallbackHdi::ConvertResultCode(const int32_t in)
{
    ResultCode hdiIn = static_cast<ResultCode>(in);
    if (hdiIn > ResultCode::VENDOR_RESULT_CODE_BEGIN) {
        IAM_LOGI("vendor hdi result code %{public}d, no covert", hdiIn);
        return static_cast<UserIam::UserAuth::ResultCode>(in);
    }

    static const std::map<ResultCode, UserIam::UserAuth::ResultCode> data = {
        {ResultCode::SUCCESS, UserIam::UserAuth::ResultCode::SUCCESS},
        {ResultCode::FAIL, UserIam::UserAuth::ResultCode::FAIL},
        {ResultCode::GENERAL_ERROR, UserIam::UserAuth::ResultCode::GENERAL_ERROR},
        {ResultCode::CANCELED, UserIam::UserAuth::ResultCode::CANCELED},
        {ResultCode::TIMEOUT, UserIam::UserAuth::ResultCode::TIMEOUT},
        {ResultCode::BUSY, UserIam::UserAuth::ResultCode::BUSY},
        {ResultCode::INVALID_PARAMETERS, UserIam::UserAuth::ResultCode::INVALID_PARAMETERS},
        {ResultCode::LOCKED, UserIam::UserAuth::ResultCode::LOCKED},
        {ResultCode::NOT_ENROLLED, UserIam::UserAuth::ResultCode::NOT_ENROLLED},
        // should be UserIam::UserAuth::ResultCode::OPERATION_NOT_SUPPORT
        {ResultCode::OPERATION_NOT_SUPPORT, UserIam::UserAuth::ResultCode::GENERAL_ERROR},
    };

    UserIam::UserAuth::ResultCode out;
    if (data.count(hdiIn) == 0) {
        out = UserIam::UserAuth::ResultCode::GENERAL_ERROR;
        IAM_LOGE("convert hdi undefined result code %{public}d to framework result code %{public}d", in, out);
        return out;
    }
    out = data.at(hdiIn);
    IAM_LOGI("covert hdi result code %{public}d to framework result code %{public}d", hdiIn, out);
    return out;
}
} // PinAuth
} // UserIam
} // OHOS