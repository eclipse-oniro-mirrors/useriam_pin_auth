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

#ifndef PINAUTH_SECRET_H
#define PINAUTH_SECRET_H

#include <cstdint>
#include <openssl/evp.h>
#include <vector>
#include "nocopyable.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
enum AuthType : uint32_t {
    ALGO_VERSION_V0 = 0,
    ALGO_VERSION_V1 = 1,
    ALGO_VERSION_V2 = 2,
    ALGO_VERSION_V3 = 3
};

class Scrypt : public NoCopyable {
public:
    explicit Scrypt(std::vector<uint8_t> algoParameter) : algoParameter_(std::move(algoParameter)) {}
    ~Scrypt() override = default;
    std::vector<uint8_t> GetScrypt(const std::vector<uint8_t> &data, uint32_t algoVersion);

private:
    bool DoScrypt(const std::vector<uint8_t> &data, uint32_t algoVersion, EVP_PKEY_CTX *pctx);
    std::vector<uint8_t> algoParameter_ = {};
};
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS

#endif // PINAUTH_SECRET_H