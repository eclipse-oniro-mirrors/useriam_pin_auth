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

/**
 * @file i_inputer_data.h
 *
 * @brief The definition of pinAuth's inputer data.
 * @since 3.1
 * @version 3.2
 */

#ifndef PINAUTH_IINPUTERDATA_H
#define PINAUTH_IINPUTERDATA_H

#include <memory>
#include <vector>
#include "nocopyable.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
class IInputerData : public NoCopyable {
public:
    /**
     * @brief Get IInputerData's instance.
     *
     * @return IInputerData's instance.
     */
    IInputerData() = default;

    /**
     * @brief Deconstructor.
     */
    ~IInputerData() override = default;

    /**
     * @brief Transfers the pin data from the pin input dialog box to the pin auth service ability.
     *
     * @param authSubType PinAuth sub type.
     * @param data Pin data.
     */
    virtual void OnSetData(int32_t authSubType, std::vector<uint8_t> data) = 0 ;
};
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS

#endif // PINAUTH_IINPUTERDATA_H
