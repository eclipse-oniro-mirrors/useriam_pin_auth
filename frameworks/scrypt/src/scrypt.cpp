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

#include "scrypt.h"
#include "bsl_params.h"
#include "bsl_errno.h"
#include "crypt_algid.h"
#include "crypt_eal_kdf.h"
#include "crypt_errno.h"
#include "crypt_params_key.h"
#include "securec.h"
#include <unordered_map>
#include "iam_logger.h"

#define LOG_TAG "PIN_AUTH_SDK"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
namespace {
constexpr uint32_t OUT_LENGTH = 64;
constexpr uint32_t SCRYPT_N_V0 = 32768;
constexpr uint32_t SCRYPT_N_V1 = 2048;
constexpr uint32_t SCRYPT_R = 8;
constexpr uint32_t SCRYPT_P = 1;
constexpr uint32_t SCRYPT_P_V3 = 2;
constexpr uint32_t PARAM_INDEX_PASSWORD = 0;
constexpr uint32_t PARAM_INDEX_SALT = 1;
constexpr uint32_t PARAM_INDEX_N = 2;
constexpr uint32_t PARAM_INDEX_R = 3;
constexpr uint32_t PARAM_INDEX_P = 4;
constexpr uint32_t PARAMS_SIZE = 6;

struct ScryptParameters {
    uint32_t scryptN;
    uint32_t scryptR;
    uint32_t scryptP;
};

std::unordered_map<uint32_t, ScryptParameters> g_version2Param_ = {
    { PIN_ALGO_VERSION_V0, { SCRYPT_N_V0, SCRYPT_R, SCRYPT_P } },
    { PIN_ALGO_VERSION_V1, { SCRYPT_N_V1, SCRYPT_R, SCRYPT_P } },
    { PIN_ALGO_VERSION_V2, { SCRYPT_N_V1, SCRYPT_R, SCRYPT_P } },
    { PIN_ALGO_VERSION_V3, { SCRYPT_N_V1, SCRYPT_R, SCRYPT_P_V3 } }
};
}

bool Scrypt::DoScrypt(const std::vector<uint8_t> &data, uint32_t algoVersion, CRYPT_EAL_KdfCtx *ctx)
{
    auto index = g_version2Param_.find(algoVersion);
    if (index == g_version2Param_.end()) {
        IAM_LOGE("version is not in g_version2Param_");
        return false;
    }
    ScryptParameters scryptParameters = index->second;
    BSL_Param params[PARAMS_SIZE] = {{0}, {0}, {0}, {0}, {0}, BSL_PARAM_END};
    if (BSL_PARAM_InitValue(&params[PARAM_INDEX_PASSWORD], CRYPT_PARAM_KDF_PASSWORD, BSL_PARAM_TYPE_OCTETS,
        reinterpret_cast<void *>(const_cast<uint8_t *>(data.data())), data.size()) != BSL_SUCCESS) {
        IAM_LOGE("BSL_PARAM_InitValue password fail");
        return false;
    }
    if (BSL_PARAM_InitValue(&params[PARAM_INDEX_SALT], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS,
        reinterpret_cast<void *>(const_cast<uint8_t *>(algoParameter_.data())), algoParameter_.size()) != BSL_SUCCESS) {
        IAM_LOGE("BSL_PARAM_InitValue salt fail");
        return false;
    }
    if (BSL_PARAM_InitValue(&params[PARAM_INDEX_N], CRYPT_PARAM_KDF_N, BSL_PARAM_TYPE_UINT32,
        &scryptParameters.scryptN, sizeof(scryptParameters.scryptN)) != BSL_SUCCESS) {
        IAM_LOGE("BSL_PARAM_InitValue N fail");
        return false;
    }
    if (BSL_PARAM_InitValue(&params[PARAM_INDEX_R], CRYPT_PARAM_KDF_R, BSL_PARAM_TYPE_UINT32,
        &scryptParameters.scryptR, sizeof(scryptParameters.scryptR)) != BSL_SUCCESS) {
        IAM_LOGE("BSL_PARAM_InitValue R fail");
        return false;
    }
    if (BSL_PARAM_InitValue(&params[PARAM_INDEX_P], CRYPT_PARAM_KDF_P, BSL_PARAM_TYPE_UINT32,
        &scryptParameters.scryptP, sizeof(scryptParameters.scryptP)) != BSL_SUCCESS) {
        IAM_LOGE("BSL_PARAM_InitValue P fail");
        return false;
    }
    if (CRYPT_EAL_KdfSetParam(ctx, params) != CRYPT_SUCCESS) {
        IAM_LOGE("CRYPT_EAL_KdfSetParam fail");
        return false;
    }

    return true;
}

std::vector<uint8_t> Scrypt::GetScrypt(const std::vector<uint8_t> &data, uint32_t algoVersion)
{
    IAM_LOGI("start");
    std::vector<uint8_t> out;
    CRYPT_EAL_KdfCtx *ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_SCRYPT);
    if (ctx == nullptr) {
        IAM_LOGE("CRYPT_EAL_KdfNewCtx fail");
        return out;
    }

    if (!DoScrypt(data, algoVersion, ctx)) {
        IAM_LOGE("DoScrypt fail");
        CRYPT_EAL_KdfFreeCtx(ctx);
        return out;
    }
    out.resize(OUT_LENGTH);
    if (CRYPT_EAL_KdfDerive(ctx, out.data(), out.size()) != CRYPT_SUCCESS) {
        IAM_LOGE("CRYPT_EAL_KdfDerive fail");
        CRYPT_EAL_KdfFreeCtx(ctx);
        (void)memset_s(out.data(), out.size(), 0, out.size());
        out.clear();
        return out;
    }

    CRYPT_EAL_KdfFreeCtx(ctx);
    return out;
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS