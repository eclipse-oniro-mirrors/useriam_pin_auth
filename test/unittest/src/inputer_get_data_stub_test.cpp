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

#include "inputer_get_data_stub_test.h"

#include "message_parcel.h"

#include "iam_common_defines.h"
#include "mock_inputer_set_data.h"
#include "mock_inputer_get_data_service.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
using namespace testing;
using namespace testing::ext;

void InputerGetDataStubTest::SetUpTestCase()
{
}

void InputerGetDataStubTest::TearDownTestCase()
{
}

void InputerGetDataStubTest::SetUp()
{
}

void InputerGetDataStubTest::TearDown()
{
}

HWTEST_F(InputerGetDataStubTest, InputerGetDataStubTestOnGetData001, TestSize.Level0)
{
    int32_t testAuthSubType = 10000;
    std::vector<uint8_t> testSalt = {1, 2, 3, 4, 5};

    MockInputerGetDataService service;
    EXPECT_CALL(service, OnGetData(_, _, _)).Times(1);
    ON_CALL(service, OnGetData)
        .WillByDefault(
            [&testAuthSubType](int32_t authSubType, const std::vector<uint8_t> &salt,
                const sptr<InputerSetData> &inputerSetData) {
                    EXPECT_EQ(authSubType, testAuthSubType);
                    EXPECT_THAT(salt, ElementsAre(1, 2, 3, 4, 5));
                    if (inputerSetData != nullptr) {
                        inputerSetData->OnSetData(authSubType, salt);
                    }
            }
        );
    MockInputerSetData *tempInputerSetData = new MockInputerSetData();
    EXPECT_NE(tempInputerSetData, nullptr);
    sptr<InputerSetData> testInputerSetData = static_cast<InputerSetData *>(tempInputerSetData);
    EXPECT_CALL(*tempInputerSetData, OnSetData(_, _)).Times(1);

    MessageParcel data;
    MessageParcel reply;

    EXPECT_TRUE(data.WriteInterfaceToken(InputerGetData::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(testAuthSubType));
    EXPECT_TRUE(data.WriteUInt8Vector(testSalt));
    EXPECT_NE(testInputerSetData->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(testInputerSetData->AsObject()));
    uint32_t code = InputerGetDataInterfaceCode::ON_GET_DATA;
    MessageOption option(MessageOption::TF_SYNC);

    EXPECT_EQ(service.OnRemoteRequest(code, data, reply, option), UserAuth::SUCCESS);
}

HWTEST_F(InputerGetDataStubTest, InputerGetDataStubTestOnGetData002, TestSize.Level0)
{
    int32_t testAuthSubType = 10000;
    std::vector<uint8_t> testSalt = {1, 2, 3, 4, 5};

    MockInputerGetDataService service;

    sptr<InputerSetData> testInputerSetData = new MockInputerSetData();
    EXPECT_NE(testInputerSetData, nullptr);

    MessageParcel data;
    MessageParcel reply;

    EXPECT_TRUE(data.WriteInt32(testAuthSubType));
    EXPECT_TRUE(data.WriteUInt8Vector(testSalt));
    EXPECT_NE(testInputerSetData->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(testInputerSetData->AsObject()));
    uint32_t code = InputerGetDataInterfaceCode::ON_GET_DATA;
    MessageOption option(MessageOption::TF_SYNC);

    EXPECT_EQ(service.OnRemoteRequest(code, data, reply, option), UserAuth::GENERAL_ERROR);
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
