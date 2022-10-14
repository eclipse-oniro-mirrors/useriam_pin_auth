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

#ifndef MOCK_INPUTER_GET_DATA_H
#define MOCK_INPUTER_GET_DATA_H

#include <gmock/gmock.h>
#include <iremote_stub.h>

#include "inputer_get_data.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
class MockInputerGetData final : public IRemoteStub<InputerGetData> {
public:
    MOCK_METHOD3(OnGetData, void(int32_t authSubType, const std::vector<uint8_t> &salt,
        const sptr<InputerSetData> &inputerSetData));
};
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
#endif // MOCK_INPUTER_GET_DATA_H