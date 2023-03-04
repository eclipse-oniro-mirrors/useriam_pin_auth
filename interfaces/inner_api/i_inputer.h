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
 * @file i_inputer.h
 *
 * @brief The definition of pinAuth's inputer.
 * @since 3.1
 * @version 3.2
 */

#ifndef PINAUTH_IINPUTER_H
#define PINAUTH_IINPUTER_H

#include "i_inputer_data.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
class IInputer {
public:

    /**
     * @brief Obtains the pin data.
     *
     * @param authSubType PinAuth sub type.
     * @param inputerData PinAuth's inputer data.
     */
    virtual void OnGetData(int32_t authSubType, std::shared_ptr<IInputerData> inputerData);
};
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS

#endif // PINAUTH_IINPUTER_H
