/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "pin_auth_stub_test.h"

#include "message_parcel.h"

#include "iam_common_defines.h"
#include "mock_inputer_get_data.h"
#include "mock_pin_auth_service.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
using namespace testing;
using namespace testing::ext;

void PinAuthStubTest::SetUpTestCase()
{
}

void PinAuthStubTest::TearDownTestCase()
{
}

void PinAuthStubTest::SetUp()
{
}

void PinAuthStubTest::TearDown()
{
}

HWTEST_F(PinAuthStubTest, PinAuthStubTestRegisterInputer, TestSize.Level0)
{
    MockPinAuthService service;
    sptr<MockInputerGetData> tempInputerGetData(new (std::nothrow) MockInputerGetData());
    EXPECT_NE(tempInputerGetData, nullptr);
    EXPECT_CALL(service, RegisterInputer(_)).Times(1);
    ON_CALL(service, RegisterInputer)
        .WillByDefault(
            [](const sptr<InputerGetData> &inputer) {
                if (inputer != nullptr) {
                    std::vector<uint8_t> algoParameter = {1, 2, 3, 4};
                    inputer->OnGetData(10000, algoParameter, nullptr, 0, false);
                }
                return true;
            }
        );
    EXPECT_CALL(*tempInputerGetData, OnGetData(_, _, _, _, _)).Times(1);

    MessageParcel data;
    MessageParcel reply;

    EXPECT_TRUE(data.WriteInterfaceToken(PinAuthInterface::GetDescriptor()));
    EXPECT_NE(tempInputerGetData->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(tempInputerGetData->AsObject()));
    uint32_t code = PinAuthInterfaceCode::REGISTER_INPUTER;
    MessageOption option(MessageOption::TF_SYNC);

    EXPECT_EQ(service.OnRemoteRequest(code, data, reply, option), UserAuth::SUCCESS);
    bool result = false;
    EXPECT_EQ(reply.ReadBool(result), true);
    EXPECT_EQ(result, true);
}

HWTEST_F(PinAuthStubTest, PinAuthStubTestUnRegisterInputer001, TestSize.Level0)
{
    MockPinAuthService service;
    EXPECT_CALL(service, UnRegisterInputer()).Times(1);

    MessageParcel data;
    MessageParcel reply;

    EXPECT_TRUE(data.WriteInterfaceToken(PinAuthInterface::GetDescriptor()));
    uint32_t code = PinAuthInterfaceCode::UNREGISTER_INPUTER;
    MessageOption option(MessageOption::TF_SYNC);

    EXPECT_EQ(service.OnRemoteRequest(code, data, reply, option), UserAuth::SUCCESS);
}

HWTEST_F(PinAuthStubTest, PinAuthStubTestUnRegisterInputer002, TestSize.Level0)
{
    MockPinAuthService service;

    MessageParcel data;
    MessageParcel reply;

    uint32_t code = PinAuthInterfaceCode::UNREGISTER_INPUTER;
    MessageOption option(MessageOption::TF_SYNC);

    EXPECT_EQ(service.OnRemoteRequest(code, data, reply, option), UserAuth::GENERAL_ERROR);
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
