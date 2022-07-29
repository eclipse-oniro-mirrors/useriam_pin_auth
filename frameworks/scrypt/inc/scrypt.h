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

#ifndef PINAUTH_SECRET_H
#define PINAUTH_SECRET_H

#include <cstdint>
#include <vector>
#include "nocopyable.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
class Scrypt : public NoCopyable {
public:
    Scrypt(std::vector<uint8_t> salt) : salt_(std::move(salt)) {}
    ~Scrypt() = default;
    std::vector<uint8_t> GetScrypt(const std::vector<uint8_t> data);

private:
    std::vector<uint8_t> salt_;
};
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS

#endif // PINAUTH_SECRET_H