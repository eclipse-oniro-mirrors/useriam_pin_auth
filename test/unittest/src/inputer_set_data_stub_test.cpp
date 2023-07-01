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

#include "inputer_set_data_stub_test.h"

#include "message_parcel.h"

#include "iam_common_defines.h"
#include "mock_inputer_data_impl.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
using namespace testing;
using namespace testing::ext;

void InputerSetDataStubTest::SetUpTestCase()
{
}

void InputerSetDataStubTest::TearDownTestCase()
{
}

void InputerSetDataStubTest::SetUp()
{
}

void InputerSetDataStubTest::TearDown()
{
}

HWTEST_F(InputerSetDataStubTest, InputerSetDataStubTestOnSetData001, TestSize.Level0)
{
    int32_t testAuthSubType = 10000;
    std::vector<uint8_t> testData = {1, 2, 3, 4, 5};

    MockInputerDataImpl inputerDataImpl;
    EXPECT_CALL(inputerDataImpl, OnSetData(_, _)).Times(1);
    ON_CALL(inputerDataImpl, OnSetData)
        .WillByDefault(
            [&testAuthSubType](int32_t authSubType, std::vector<uint8_t> data) {
                EXPECT_EQ(authSubType, testAuthSubType);
                EXPECT_THAT(data, ElementsAre(1, 2, 3, 4, 5));
            }
        );
    
    MessageParcel data;
    MessageParcel reply;

    EXPECT_TRUE(data.WriteInterfaceToken(InputerSetData::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(testAuthSubType));
    EXPECT_TRUE(data.WriteUInt8Vector(testData));
    uint32_t code = InputerSetDataInterfaceCode::ON_SET_DATA;
    MessageOption option(MessageOption::TF_SYNC);

    EXPECT_EQ(inputerDataImpl.OnRemoteRequest(code, data, reply, option), UserAuth::SUCCESS);
}

HWTEST_F(InputerSetDataStubTest, InputerSetDataStubTestOnSetData002, TestSize.Level0)
{
    int32_t testAuthSubType = 10000;
    std::vector<uint8_t> testData = {1, 2, 3, 4, 5};

    MockInputerDataImpl inputerDataImpl;

    MessageParcel data;
    MessageParcel reply;

    EXPECT_TRUE(data.WriteInt32(testAuthSubType));
    EXPECT_TRUE(data.WriteUInt8Vector(testData));
    uint32_t code = InputerSetDataInterfaceCode::ON_SET_DATA;
    MessageOption option(MessageOption::TF_SYNC);

    EXPECT_EQ(inputerDataImpl.OnRemoteRequest(code, data, reply, option), UserAuth::GENERAL_ERROR);
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
