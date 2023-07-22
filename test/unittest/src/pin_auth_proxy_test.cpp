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

#include "pin_auth_proxy_test.h"

#include "iam_common_defines.h"
#include "iam_ptr.h"
#include "mock_inputer_get_data_service.h"
#include "mock_remote_object.h"
#include "mock_pin_auth_service.h"
#include "pin_auth_proxy.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
using namespace testing;
using namespace testing::ext;

void PinAuthProxyTest::SetUpTestCase()
{
}

void PinAuthProxyTest::TearDownTestCase()
{
}

void PinAuthProxyTest::SetUp()
{
}

void PinAuthProxyTest::TearDown()
{
}

HWTEST_F(PinAuthProxyTest, PinAuthProxyTestRegisterInputer001, TestSize.Level0)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<PinAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    sptr<InputerGetData> testInputerGetData(new (std::nothrow) MockInputerGetDataService());
    EXPECT_NE(testInputerGetData, nullptr);

    auto service = Common::MakeShared<MockPinAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, RegisterInputer(_))
        .Times(Exactly(1))
        .WillOnce([&testInputerGetData](const sptr<InputerGetData> &inputer) {
            EXPECT_EQ(inputer, testInputerGetData);
            return true;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            return service->OnRemoteRequest(code, data, reply, option);
        });
    EXPECT_EQ(proxy->RegisterInputer(testInputerGetData), true);
}

HWTEST_F(PinAuthProxyTest, PinAuthProxyTestRegisterInputer002, TestSize.Level0)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<PinAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    sptr<InputerGetData> testInputerGetData(nullptr);

    EXPECT_EQ(proxy->RegisterInputer(testInputerGetData), false);
}

HWTEST_F(PinAuthProxyTest, PinAuthProxyTestUnRegisterInputer, TestSize.Level0)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<PinAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    sptr<InputerGetData> testInputerGetData(new (std::nothrow) MockInputerGetDataService());
    EXPECT_NE(testInputerGetData, nullptr);

    auto service = Common::MakeShared<MockPinAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, UnRegisterInputer()).Times(1);

    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            return service->OnRemoteRequest(code, data, reply, option);
        });
    proxy->UnRegisterInputer();
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
