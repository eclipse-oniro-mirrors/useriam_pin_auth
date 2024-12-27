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

namespace {
void GetMockInputerGetDataService(MockInputerGetDataService *service, int32_t *testErrorCode)
{
    ON_CALL(*service, OnGetData)
        .WillByDefault([&testErrorCode](const InputerGetDataParam &getDataParam) {
            if (getDataParam.inputerSetData != nullptr) {
                getDataParam.inputerSetData->OnSetData(
                    getDataParam.authSubType, getDataParam.algoParameter, *testErrorCode);
            }
        }
    );
}
}

HWTEST_F(InputerGetDataStubTest, InputerGetDataStubTestOnGetData001, TestSize.Level0)
{
    int32_t testAuthSubType = 10000;
    std::vector<uint8_t> testSalt = {1, 2, 3, 4, 5};
    std::vector<uint8_t> testChallenge = {2, 3, 4, 5, 6};
    uint32_t testAlgoVersion = 0;
    GetDataMode testMode = GET_DATA_MODE_ALL_IN_ONE_PIN_AUTH;

    MockInputerGetDataService service;

    sptr<MockInputerSetData> tempInputerSetData(new (std::nothrow) MockInputerSetData());
    EXPECT_NE(tempInputerSetData, nullptr);

    MessageParcel data;
    MessageParcel reply;

    EXPECT_TRUE(data.WriteInterfaceToken(InputerGetData::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(testMode));
    EXPECT_TRUE(data.WriteInt32(testAuthSubType));
    EXPECT_TRUE(data.WriteUint32(testAlgoVersion));
    EXPECT_TRUE(data.WriteUInt8Vector(testSalt));
    EXPECT_TRUE(data.WriteUInt8Vector(testChallenge));
    ASSERT_NE(tempInputerSetData->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(tempInputerSetData->AsObject()));

    uint32_t code = InputerGetDataInterfaceCode::ON_GET_DATA;
    MessageOption option(MessageOption::TF_SYNC);

    EXPECT_EQ(service.OnRemoteRequest(code, data, reply, option), UserAuth::SUCCESS);
}

HWTEST_F(InputerGetDataStubTest, InputerGetDataStubTestOnGetData002, TestSize.Level0)
{
    int32_t testAuthSubType = 10000;
    std::vector<uint8_t> testSalt = {1, 2, 3, 4, 5};
    uint32_t testAlgoVersion = 0;
    bool testIsEnroll = false;

    MockInputerGetDataService service;

    sptr<InputerSetData> testInputerSetData(new (std::nothrow) MockInputerSetData());
    EXPECT_NE(testInputerSetData, nullptr);

    MessageParcel data;
    MessageParcel reply;

    EXPECT_TRUE(data.WriteInt32(testAuthSubType));
    EXPECT_TRUE(data.WriteUInt8Vector(testSalt));
    EXPECT_NE(testInputerSetData->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteUint32(testAlgoVersion));
    EXPECT_TRUE(data.WriteBool(testIsEnroll));
    EXPECT_TRUE(data.WriteRemoteObject(testInputerSetData->AsObject()));
    uint32_t code = InputerGetDataInterfaceCode::ON_GET_DATA;
    MessageOption option(MessageOption::TF_SYNC);

    EXPECT_EQ(service.OnRemoteRequest(code, data, reply, option), UserAuth::GENERAL_ERROR);
}

HWTEST_F(InputerGetDataStubTest, OnRemoteRequestTest001, TestSize.Level0)
{
    int32_t userId = 1;
    int32_t authIntent = 1;
    std::string complexityReg = "";
    int32_t testAuthSubType = 10000;
    std::vector<uint8_t> testSalt = {1, 2, 3, 4, 5};
    std::vector<uint8_t> testChallenge = {2, 3, 4, 5, 6};
    uint32_t testAlgoVersion = 0;
    GetDataMode testMode = GET_DATA_MODE_ALL_IN_ONE_PIN_AUTH;
    int32_t testErrorCode = 0;

    MockInputerGetDataService service;
    EXPECT_CALL(service, OnGetData(_)).Times(1);
    ON_CALL(service, OnGetData)
        .WillByDefault(
            [&testAuthSubType, &testAlgoVersion, &testMode, &testErrorCode](
                const InputerGetDataParam &getDataParam) {
                    EXPECT_EQ(getDataParam.authSubType, testAuthSubType);
                    EXPECT_THAT(getDataParam.algoParameter, ElementsAre(1, 2, 3, 4, 5));
                    EXPECT_THAT(getDataParam.challenge, ElementsAre(2, 3, 4, 5, 6));
                    EXPECT_EQ(getDataParam.algoVersion, testAlgoVersion);
                    EXPECT_EQ(getDataParam.mode, testMode);
                    if (getDataParam.inputerSetData != nullptr) {
                        getDataParam.inputerSetData->OnSetData(
                            getDataParam.authSubType, getDataParam.algoParameter, testErrorCode);
                    }
            }
        );

    sptr<MockInputerSetData> tempInputerSetData(new (std::nothrow) MockInputerSetData());
    EXPECT_NE(tempInputerSetData, nullptr);
    EXPECT_CALL(*tempInputerSetData, OnSetData(_, _, _)).Times(1);

    MessageParcel data;
    MessageParcel reply;

    EXPECT_TRUE(data.WriteInterfaceToken(InputerGetData::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(testMode));
    EXPECT_TRUE(data.WriteInt32(testAuthSubType));
    EXPECT_TRUE(data.WriteUint32(testAlgoVersion));
    EXPECT_TRUE(data.WriteUInt8Vector(testSalt));
    EXPECT_TRUE(data.WriteUInt8Vector(testChallenge));
    EXPECT_TRUE(data.WriteInt32(userId));
    EXPECT_TRUE(data.WriteString(complexityReg));
    EXPECT_TRUE(data.WriteInt32(authIntent));
    ASSERT_NE(tempInputerSetData->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(tempInputerSetData->AsObject()));

    uint32_t code = 1;
    MessageOption option(MessageOption::TF_SYNC);

    EXPECT_EQ(service.OnRemoteRequest(code, data, reply, option), 0);
}

HWTEST_F(InputerGetDataStubTest, OnGetDataStubTest001, TestSize.Level0)
{
    int32_t testAuthSubType = 10000;
    std::vector<uint8_t> testSalt = {1, 2, 3, 4, 5};
    std::vector<uint8_t> testChallenge = {2, 3, 4, 5, 6};
    GetDataMode testMode = GET_DATA_MODE_ALL_IN_ONE_PIN_AUTH;
    int32_t testErrorCode = 0;

    MockInputerGetDataService service;
    GetMockInputerGetDataService(&service, &testErrorCode);

    sptr<MockInputerSetData> tempInputerSetData(new (std::nothrow) MockInputerSetData());
    EXPECT_NE(tempInputerSetData, nullptr);

    MessageParcel data;
    MessageParcel reply;
    EXPECT_TRUE(data.WriteInterfaceToken(InputerGetData::GetDescriptor()));
    EXPECT_NO_THROW(service.OnGetDataStub(data, reply));

    MessageParcel data1;
    EXPECT_TRUE(data1.WriteInt32(testMode));
    EXPECT_TRUE(data1.WriteInterfaceToken(InputerGetData::GetDescriptor()));
    EXPECT_NO_THROW(service.OnGetDataStub(data1, reply));

    MessageParcel data2;
    EXPECT_TRUE(data2.WriteInt32(testMode));
    EXPECT_TRUE(data2.WriteInt32(testAuthSubType));
    EXPECT_TRUE(data2.WriteInterfaceToken(InputerGetData::GetDescriptor()));
    EXPECT_NO_THROW(service.OnGetDataStub(data2, reply));

    MessageParcel data3;
    EXPECT_TRUE(data3.WriteInt32(testMode));
    EXPECT_TRUE(data3.WriteInt32(testAuthSubType));
    EXPECT_TRUE(data3.WriteUInt8Vector(testSalt));
    EXPECT_TRUE(data3.WriteInterfaceToken(InputerGetData::GetDescriptor()));
    EXPECT_NO_THROW(service.OnGetDataStub(data3, reply));

    MessageParcel data4;
    EXPECT_TRUE(data4.WriteInt32(testMode));
    EXPECT_TRUE(data4.WriteInt32(testAuthSubType));
    EXPECT_TRUE(data4.WriteUInt8Vector(testSalt));
    EXPECT_TRUE(data4.WriteUInt8Vector(testChallenge));
    EXPECT_TRUE(data4.WriteInterfaceToken(InputerGetData::GetDescriptor()));
    EXPECT_NO_THROW(service.OnGetDataStub(data4, reply));

    MessageParcel data5;
    EXPECT_TRUE(data5.WriteInt32(testMode));
    EXPECT_TRUE(data5.WriteInt32(testAuthSubType));
    EXPECT_TRUE(data5.WriteUInt8Vector(testSalt));
    EXPECT_TRUE(data5.WriteUInt8Vector(testChallenge));
    EXPECT_TRUE(data5.WriteRemoteObject(tempInputerSetData->AsObject()));
    EXPECT_NO_THROW(service.OnGetDataStub(data5, reply));
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
