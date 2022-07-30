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
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/kdf.h>
#include "iam_logger.h"

#define LOG_LABEL OHOS::UserIam::Common::LABEL_PIN_AUTH_SDK

namespace OHOS {
namespace UserIam {
namespace PinAuth {
namespace {
    constexpr int32_t OUT_LENGTH = 64;
    constexpr int32_t SCRYPT_N = 32768;
    constexpr int32_t SCRYPT_R = 3;
    constexpr int32_t SCRYPT_P = 1;
}

std::vector<uint8_t> Scrypt::GetScrypt(const std::vector<uint8_t> data)
{
    IAM_LOGI("start");
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SCRYPT, NULL);
    if (EVP_PKEY_derive_init(pctx) <= 0) {
        IAM_LOGE("EVP_PKEY_derive_init fail");
        return {};
    }
    if (EVP_PKEY_CTX_set1_pbe_pass(pctx, data.data(), data.size()) <= 0) {
        IAM_LOGE("EVP_PKEY_CTX_set1_pbe_pass fail");
        EVP_PKEY_CTX_free(pctx);
        return {};
    }
    if (EVP_PKEY_CTX_set1_scrypt_salt(pctx, salt_.data(), salt_.size()) <= 0) {
        IAM_LOGE("EVP_PKEY_CTX_set1_scrypt_salt fail");
        EVP_PKEY_CTX_free(pctx);
        return {};
    }
    if (EVP_PKEY_CTX_set_scrypt_N(pctx, SCRYPT_N) <= 0) {
        IAM_LOGE("EVP_PKEY_CTX_set_scrypt_N fail");
        EVP_PKEY_CTX_free(pctx);
        return {};
    }
    if (EVP_PKEY_CTX_set_scrypt_r(pctx, SCRYPT_R) <= 0) {
        IAM_LOGE("EVP_PKEY_CTX_set_scrypt_r fail");
        EVP_PKEY_CTX_free(pctx);
        return {};
    }
    if (EVP_PKEY_CTX_set_scrypt_p(pctx, SCRYPT_P) <= 0) {
        IAM_LOGE("EVP_PKEY_CTX_set_scrypt_p fail");
        EVP_PKEY_CTX_free(pctx);
        return {};
    }

    std::vector<uint8_t> out(OUT_LENGTH);
    size_t outlen = out.size();
    if (EVP_PKEY_derive(pctx, out.data(), &outlen) <= 0) {
        IAM_LOGE("EVP_PKEY_derive fail");
        EVP_PKEY_CTX_free(pctx);
        return {};
    }

    EVP_PKEY_CTX_free(pctx);
    return out;
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS