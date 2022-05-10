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
namespace UserIAM {
namespace PinAuth {
PinAuthExecutorCallbackHdi::PinAuthExecutorCallbackHdi(std::shared_ptr<UserAuth::IExecuteCallback>
    frameworkCallback, std::shared_ptr<PinAuthExecutorHdi> pinAuthExecutorHdi, uint64_t callerUid)
    : frameworkCallback_(frameworkCallback), pinAuthExecutorHdi_(pinAuthExecutorHdi), callerUid_(callerUid) {}

int32_t PinAuthExecutorCallbackHdi::OnResult(int32_t code, const std::vector<uint8_t>& extraInfo)
{
    IAM_LOGI("OnResult %{public}d", code);
    UserIAM::ResultCode retCode = ConvertResultCode(code);
    frameworkCallback_->OnResult(retCode, extraInfo);
    return HDF_SUCCESS;
}

int32_t PinAuthExecutorCallbackHdi::OnGetData(uint64_t scheduleId, const std::vector<uint8_t>& salt,
    uint64_t authSubType)
{
    IAM_LOGI("Start callerUid_ is  0xXXXX%{public}04" PRIx64 " ", callerUid_);
    sptr<IRemoteInputer> inputer = PinAuthManager::GetInstance().getInputerLock(callerUid_);
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

UserIAM::ResultCode PinAuthExecutorCallbackHdi::ConvertResultCode(const int32_t in)
{
    ResultCode hdiIn = static_cast<ResultCode>(in);
    if (hdiIn > ResultCode::VENDOR_RESULT_CODE_BEGIN) {
        IAM_LOGI("vendor hdi result code %{public}d, no covert", hdiIn);
        return static_cast<UserIAM::ResultCode>(in);
    }

    static const std::map<ResultCode, UserIAM::ResultCode> data = {
        {ResultCode::SUCCESS, UserIAM::ResultCode::SUCCESS},
        {ResultCode::FAIL, UserIAM::ResultCode::FAIL},
        {ResultCode::GENERAL_ERROR, UserIAM::ResultCode::GENERAL_ERROR},
        {ResultCode::CANCELED, UserIAM::ResultCode::CANCELED},
        {ResultCode::TIMEOUT, UserIAM::ResultCode::TIMEOUT},
        {ResultCode::BUSY, UserIAM::ResultCode::BUSY},
        {ResultCode::INVALID_PARAMETERS, UserIAM::ResultCode::INVALID_PARAMETERS},
        {ResultCode::LOCKED, UserIAM::ResultCode::LOCKED},
        {ResultCode::NOT_ENROLLED, UserIAM::ResultCode::NOT_ENROLLED},
        // should be UserIAM::ResultCode::OPERATION_NOT_SUPPORT
        {ResultCode::OPERATION_NOT_SUPPORT, UserIAM::ResultCode::GENERAL_ERROR},
    };

    UserIAM::ResultCode out;
    if (data.count(hdiIn) == 0) {
        out = UserIAM::ResultCode::GENERAL_ERROR;
        IAM_LOGE("convert hdi undefined result code %{public}d to framework result code %{public}d", in, out);
        return out;
    }
    out = data.at(hdiIn);
    IAM_LOGI("covert hdi result code %{public}d to framework result code %{public}d", hdiIn, out);
    return out;
}
} // PinAuth
} // UserIAM
} // OHOS