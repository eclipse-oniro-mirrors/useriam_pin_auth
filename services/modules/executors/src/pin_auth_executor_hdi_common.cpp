/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "pin_auth_executor_hdi_common.h"

#include <map>

#include "iam_logger.h"

#define LOG_TAG "PIN_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
UserAuth::ResultCode ConvertAuthType(AuthType in, UserAuth::AuthType &out)
{
    static const std::map<AuthType, UserAuth::AuthType> data = {
        {AuthType::PIN, UserAuth::AuthType::PIN},
    };
    auto it = data.find(in);
    if (it == data.end()) {
        IAM_LOGE("authType %{public}d is invalid", in);
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    out = it->second;
    return UserAuth::ResultCode::SUCCESS;
}

UserAuth::ResultCode ConvertExecutorRole(ExecutorRole in, UserAuth::ExecutorRole &out)
{
    static const std::map<ExecutorRole, UserAuth::ExecutorRole> data = {
        {ExecutorRole::COLLECTOR, UserAuth::ExecutorRole::COLLECTOR},
        {ExecutorRole::VERIFIER, UserAuth::ExecutorRole::VERIFIER},
        {ExecutorRole::ALL_IN_ONE, UserAuth::ExecutorRole::ALL_IN_ONE},
    };
    auto it = data.find(in);
    if (it == data.end()) {
        IAM_LOGE("executorRole %{public}d is invalid", in);
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    out = it->second;
    return UserAuth::ResultCode::SUCCESS;
}

UserAuth::ResultCode ConvertExecutorSecureLevel(ExecutorSecureLevel in, UserAuth::ExecutorSecureLevel &out)
{
    static const std::map<ExecutorSecureLevel, UserAuth::ExecutorSecureLevel> data = {
        {ExecutorSecureLevel::ESL0, UserAuth::ExecutorSecureLevel::ESL0},
        {ExecutorSecureLevel::ESL1, UserAuth::ExecutorSecureLevel::ESL1},
        {ExecutorSecureLevel::ESL2, UserAuth::ExecutorSecureLevel::ESL2},
        {ExecutorSecureLevel::ESL3, UserAuth::ExecutorSecureLevel::ESL3},
    };
    auto it = data.find(in);
    if (it == data.end()) {
        IAM_LOGE("executorSecureLevel %{public}d is invalid", in);
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    out = it->second;
    return UserAuth::ResultCode::SUCCESS;
}

UserAuth::ResultCode MoveHdiExecutorInfo(ExecutorInfo &in, UserAuth::ExecutorInfo &out)
{
    out.executorSensorHint = static_cast<uint32_t>(in.sensorId);
    out.executorMatcher = in.executorMatcher;
    int32_t ret = ConvertExecutorRole(static_cast<ExecutorRole>(in.executorRole), out.executorRole);
    if (ret != UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("executorProxy is null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    ret = ConvertAuthType(static_cast<AuthType>(in.authType), out.authType);
    if (ret != UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("ConvertAuthType fail ret=%{public}d", ret);
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    ret = ConvertExecutorSecureLevel(static_cast<ExecutorSecureLevel>(in.esl), out.esl);
    if (ret != UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("ConvertExecutorSecureLevel fail ret=%{public}d", ret);
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    out.maxTemplateAcl = in.maxTemplateAcl;
    in.publicKey.swap(out.publicKey);
    return UserAuth::ResultCode::SUCCESS;
}

UserAuth::ResultCode ConvertHdiResultCode(int32_t in)
{
    HDF_STATUS hdfIn = static_cast<HDF_STATUS>(in);
    static const std::map<HDF_STATUS, UserAuth::ResultCode> data = {
        {HDF_SUCCESS, UserAuth::ResultCode::SUCCESS},
        {HDF_FAILURE, UserAuth::ResultCode::GENERAL_ERROR},
        {HDF_ERR_TIMEOUT, UserAuth::ResultCode::TIMEOUT},
        {HDF_ERR_QUEUE_FULL, UserAuth::ResultCode::BUSY},
        {HDF_ERR_DEVICE_BUSY, UserAuth::ResultCode::BUSY},
        {HDF_ERR_INVALID_PARAM, UserAuth::ResultCode::INVALID_PARAMETERS},
    };

    UserAuth::ResultCode out;
    auto it = data.find(hdfIn);
    if (it == data.end()) {
        out = UserAuth::ResultCode::GENERAL_ERROR;
    } else {
        out = it->second;
    }
    IAM_LOGI("covert hdi result code %{public}d to framework result code %{public}d", in, out);
    return out;
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
