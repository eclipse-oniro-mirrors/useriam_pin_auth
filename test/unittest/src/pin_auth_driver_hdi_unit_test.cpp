/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"

#include "iam_logger.h"
#include "iam_ptr.h"

#include "pin_auth_driver_hdi.h"
#include "mock_pin_auth_interface_adapter.h"
#include "mock_iexecutor.h"
#include "mock_ipin_auth_interface.h"

#define LOG_LABEL OHOS::UserIam::Common::LABEL_PIN_AUTH_SA

using namespace testing;
using namespace testing::ext;
using namespace OHOS::UserIam::Common;

namespace OHOS {
namespace UserIam {
namespace PinAuth {
class PinAuthDriverHdiUnitTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void PinAuthDriverHdiUnitTest::SetUpTestCase()
{
}

void PinAuthDriverHdiUnitTest::TearDownTestCase()
{
}

void PinAuthDriverHdiUnitTest::SetUp()
{
}

void PinAuthDriverHdiUnitTest::TearDown()
{
}

HWTEST_F(PinAuthDriverHdiUnitTest, PinAuthDriverHdi_GetExecutorListTest_001, TestSize.Level0)
{
    PinAuthDriverHdi driverHdi(nullptr);
    std::vector<std::shared_ptr<UserAuth::IAuthExecutorHdi>> executorList;
    driverHdi.GetExecutorList(executorList);
    EXPECT_TRUE(executorList.size() == 0);
}

HWTEST_F(PinAuthDriverHdiUnitTest, PinAuthDriverHdi_GetExecutorListTest_002, TestSize.Level0)
{
    auto adapter = MakeShared<MockPinAuthInterfaceAdapter>();
    ASSERT_TRUE(adapter != nullptr);
    EXPECT_CALL(*adapter, Get()).Times(Exactly(1)).WillOnce(Return(nullptr));

    PinAuthDriverHdi driverHdi(adapter);
    std::vector<std::shared_ptr<UserAuth::IAuthExecutorHdi>> executorList;
    driverHdi.GetExecutorList(executorList);
    EXPECT_TRUE(executorList.size() == 0);
}

HWTEST_F(PinAuthDriverHdiUnitTest, PinAuthDriverHdi_GetExecutorListTest_003, TestSize.Level0)
{
    sptr<MockIPinAuthInterface> interface(new (std::nothrow) MockIPinAuthInterface());
    ASSERT_TRUE(interface != nullptr);
    EXPECT_CALL(*interface, GetExecutorListV1_1(_)).Times(Exactly(1));

    auto adapter = MakeShared<MockPinAuthInterfaceAdapter>();
    ASSERT_TRUE(adapter != nullptr);
    EXPECT_CALL(*adapter, Get()).Times(Exactly(1)).WillOnce(Return(interface));

    PinAuthDriverHdi driverHdi(adapter);
    std::vector<std::shared_ptr<UserAuth::IAuthExecutorHdi>> executorList;
    driverHdi.GetExecutorList(executorList);
    EXPECT_TRUE(executorList.size() == 0);
}

HWTEST_F(PinAuthDriverHdiUnitTest, PinAuthDriverHdi_GetExecutorListTest_004, TestSize.Level0)
{
    sptr<MockIPinAuthInterface> interface(new (std::nothrow) MockIPinAuthInterface());
    ASSERT_TRUE(interface != nullptr);
    EXPECT_CALL(*interface, GetExecutorListV1_1(_)).Times(Exactly(1)).WillOnce([](std::vector<sptr<IExecutor>> &list) {
        return static_cast<int32_t>(HDF_FAILURE);
    });

    auto adapter = MakeShared<MockPinAuthInterfaceAdapter>();
    ASSERT_TRUE(adapter != nullptr);
    EXPECT_CALL(*adapter, Get()).Times(Exactly(1)).WillOnce(Return(interface));

    PinAuthDriverHdi driverHdi(adapter);
    std::vector<std::shared_ptr<UserAuth::IAuthExecutorHdi>> executorList;
    driverHdi.GetExecutorList(executorList);
    EXPECT_TRUE(executorList.size() == 0);
}

HWTEST_F(PinAuthDriverHdiUnitTest, PinAuthDriverHdi_GetExecutorListTest_005, TestSize.Level0)
{
    sptr<MockIPinAuthInterface> interface(new (std::nothrow) MockIPinAuthInterface());
    ASSERT_TRUE(interface != nullptr);
    EXPECT_CALL(*interface, GetExecutorListV1_1(_)).Times(Exactly(1)).WillOnce([](std::vector<sptr<IExecutor>> &list) {
        return static_cast<int32_t>(HDF_SUCCESS);
    });

    auto adapter = MakeShared<MockPinAuthInterfaceAdapter>();
    ASSERT_TRUE(adapter != nullptr);
    EXPECT_CALL(*adapter, Get()).Times(Exactly(1)).WillOnce(Return(interface));

    PinAuthDriverHdi driverHdi(adapter);
    std::vector<std::shared_ptr<UserAuth::IAuthExecutorHdi>> executorList;
    driverHdi.GetExecutorList(executorList);
    EXPECT_TRUE(executorList.size() == 0);
}

HWTEST_F(PinAuthDriverHdiUnitTest, PinAuthDriverHdi_GetExecutorListTest_006, TestSize.Level0)
{
    sptr<MockIPinAuthInterface> interface(new (std::nothrow) MockIPinAuthInterface());
    ASSERT_TRUE(interface != nullptr);
    EXPECT_CALL(*interface, GetExecutorListV1_1(_)).Times(Exactly(1)).WillOnce([](std::vector<sptr<IExecutor>> &list) {
        auto executor = sptr<IExecutor>(new (std::nothrow) MockIExecutor());
        EXPECT_TRUE(executor != nullptr);
        list.push_back(executor);
        return static_cast<int32_t>(HDF_SUCCESS);
    });

    auto adapter = MakeShared<MockPinAuthInterfaceAdapter>();
    ASSERT_TRUE(adapter != nullptr);
    EXPECT_CALL(*adapter, Get()).Times(Exactly(1)).WillOnce(Return(interface));

    PinAuthDriverHdi driverHdi(adapter);
    std::vector<std::shared_ptr<UserAuth::IAuthExecutorHdi>> executorList;
    driverHdi.GetExecutorList(executorList);
    EXPECT_TRUE(executorList.size() == 1);
}

HWTEST_F(PinAuthDriverHdiUnitTest, PinAuthDriverHdi_GetExecutorListTest_007, TestSize.Level0)
{
    sptr<MockIPinAuthInterface> interface(new (std::nothrow) MockIPinAuthInterface());
    ASSERT_TRUE(interface != nullptr);
    EXPECT_CALL(*interface, GetExecutorListV1_1(_)).Times(Exactly(1)).WillOnce([](std::vector<sptr<IExecutor>> &list) {
        list.push_back(sptr<IExecutor>(nullptr));
        auto executor = sptr<IExecutor>(new (std::nothrow) MockIExecutor());
        EXPECT_TRUE(executor != nullptr);
        list.push_back(executor);
        list.push_back(sptr<IExecutor>(nullptr));
        executor = sptr<IExecutor>(new (std::nothrow) MockIExecutor());
        EXPECT_TRUE(executor != nullptr);
        list.push_back(executor);
        return static_cast<int32_t>(HDF_SUCCESS);
    });

    auto adapter = MakeShared<MockPinAuthInterfaceAdapter>();
    ASSERT_TRUE(adapter != nullptr);
    EXPECT_CALL(*adapter, Get()).Times(Exactly(1)).WillOnce(Return(interface));

    PinAuthDriverHdi driverHdi(adapter);
    std::vector<std::shared_ptr<UserAuth::IAuthExecutorHdi>> executorList;
    driverHdi.GetExecutorList(executorList);
    EXPECT_TRUE(executorList.size() == 2);
}

HWTEST_F(PinAuthDriverHdiUnitTest, PinAuthDriverHdi_GetExecutorListTest_008, TestSize.Level0)
{
    sptr<MockIPinAuthInterface> interface(new (std::nothrow) MockIPinAuthInterface());
    ASSERT_TRUE(interface != nullptr);
    EXPECT_CALL(*interface, GetExecutorListV1_1(_)).Times(Exactly(1)).WillOnce([](std::vector<sptr<IExecutor>> &list) {
        auto executor = sptr<IExecutor>(new (std::nothrow) MockIExecutor());
        EXPECT_TRUE(executor != nullptr);
        list.push_back(executor);
        return static_cast<int32_t>(HDF_FAILURE);
    });

    auto adapter = Common::MakeShared<MockPinAuthInterfaceAdapter>();
    ASSERT_TRUE(adapter != nullptr);
    EXPECT_CALL(*adapter, Get()).Times(Exactly(1)).WillOnce(Return(interface));

    PinAuthDriverHdi driverHdi(adapter);
    std::vector<std::shared_ptr<UserAuth::IAuthExecutorHdi>> executorList;
    driverHdi.GetExecutorList(executorList);
    EXPECT_TRUE(executorList.size() == 0);
}

HWTEST_F(PinAuthDriverHdiUnitTest, PinAuthDriverHdi_OnHdiDisconnectTest_001, TestSize.Level0)
{
    auto driverHdi = MakeShared<PinAuthDriverHdi>(nullptr);
    ASSERT_TRUE(driverHdi != nullptr);
    driverHdi->OnHdiDisconnect();
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
