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

#include "scrypt.h"
#include <openssl/ossl_typ.h>
#include <openssl/kdf.h>
#include "securec.h"
#include <unordered_map>
#include "iam_logger.h"

#define LOG_LABEL OHOS::UserIam::Common::LABEL_PIN_AUTH_SDK

namespace OHOS {
namespace UserIam {
namespace PinAuth {
namespace {
constexpr uint32_t ALGO_VERSION_V0 = 0;
constexpr uint32_t ALGO_VERSION_V1 = 1;
constexpr uint32_t OUT_LENGTH = 64;
constexpr uint32_t SCRYPT_N_V0 = 32768;
constexpr uint32_t SCRYPT_N_V1 = 2048;
constexpr uint32_t SCRYPT_R = 8;
constexpr uint32_t SCRYPT_P = 1;

struct ScryptParameters {
    int32_t scryptN;
    int32_t scryptR;
    int32_t scryptP;
};

std::unordered_map<uint32_t, ScryptParameters> g_version2Param_ = {
    { ALGO_VERSION_V0, { SCRYPT_N_V0, SCRYPT_R, SCRYPT_P } },
    { ALGO_VERSION_V1, { SCRYPT_N_V1, SCRYPT_R, SCRYPT_P } }
};
}

bool Scrypt::DoScrypt(std::vector<uint8_t> data, uint32_t algoVersion, EVP_PKEY_CTX *pctx)
{
    auto index = g_version2Param_.find(algoVersion);
    if (index == g_version2Param_.end()) {
        IAM_LOGE("version is not in g_version2Param_");
        return false;
    }
    ScryptParameters scryptParameters = index->second;
    if (EVP_PKEY_CTX_set1_pbe_pass(pctx, reinterpret_cast<const char *>(data.data()), data.size()) <= 0) {
        IAM_LOGE("EVP_PKEY_CTX_set1_pbe_pass fail");
        return false;
    }
    if (EVP_PKEY_CTX_set1_scrypt_salt(pctx, algoParameter_.data(), algoParameter_.size()) <= 0) {
        IAM_LOGE("EVP_PKEY_CTX_set1_scrypt_salt fail");
        return false;
    }
    if (EVP_PKEY_CTX_set_scrypt_N(pctx, scryptParameters.scryptN) <= 0) {
        IAM_LOGE("EVP_PKEY_CTX_set_scrypt_N fail");
        return false;
    }
    if (EVP_PKEY_CTX_set_scrypt_r(pctx, scryptParameters.scryptR) <= 0) {
        IAM_LOGE("EVP_PKEY_CTX_set_scrypt_r fail");
        return false;
    }
    if (EVP_PKEY_CTX_set_scrypt_p(pctx, scryptParameters.scryptP) <= 0) {
        IAM_LOGE("EVP_PKEY_CTX_set_scrypt_p fail");
        return false;
    }

    return true;
}

void Scrypt::ClearPinData(std::vector<uint8_t> &data)
{
    // Delete the data in the vector completely
    (void)memset_s(data.data(), data.size(), 0, data.size());
    data.clear();
    (void)memset_s(algoParameter_.data(), algoParameter_.size(), 0, algoParameter_.size());
    algoParameter_.clear();
}

std::vector<uint8_t> Scrypt::GetScrypt(std::vector<uint8_t> data, uint32_t algoVersion)
{
    IAM_LOGI("start");
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SCRYPT, NULL);
    if (EVP_PKEY_derive_init(pctx) <= 0) {
        ClearPinData(data);
        IAM_LOGE("EVP_PKEY_derive_init fail");
        return {};
    }

    if (!DoScrypt(data, algoVersion, pctx)) {
        IAM_LOGE("DoScrypt fail");
        ClearPinData(data);
        EVP_PKEY_CTX_free(pctx);
        return {};
    }
    std::vector<uint8_t> out(OUT_LENGTH);
    size_t outlen = out.size();
    if (EVP_PKEY_derive(pctx, out.data(), &outlen) <= 0) {
        IAM_LOGE("EVP_PKEY_derive fail");
        ClearPinData(data);
        EVP_PKEY_CTX_free(pctx);
        return {};
    }

    ClearPinData(data);
    EVP_PKEY_CTX_free(pctx);
    return out;
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS