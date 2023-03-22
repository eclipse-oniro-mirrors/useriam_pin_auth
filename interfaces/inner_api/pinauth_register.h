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
 * @file pinauth_register.h
 *
 * @brief APIs for managing input dialog boxes.
 * @since 3.1
 * @version 3.2
 */

#ifndef PINAUTH_REGISTER_H
#define PINAUTH_REGISTER_H

#include "i_inputer.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
class PinAuthRegister {
public:
    /**
     * @brief Get PinAuthRegister instance.
     *
     * @return PinAuthRegister's instance.
     */
    static PinAuthRegister &GetInstance();

    /**
     * @brief Deconstructor.
     */
    virtual ~PinAuthRegister() = default;

    /*
     * @brief Register inputer that used to obtain pin data.
     *
     * @param inputer Used to obtain pin data.
     * @return Is it successful.
     */
    virtual bool RegisterInputer(std::shared_ptr<IInputer> inputer) = 0;

    /*
     * @brief UnRegister inputer that used to obtain pin data.
     */
    virtual void UnRegisterInputer() = 0;
};
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS

#endif // PINAUTH_REGISTER_H
