/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

import{AsyncCallback} from './basic';

declare namespace pinAuth
{
    /**
     * constructor.
     *
     * @return Constructor to get the userauth class instance
     */
    function constructor() : PINAuth;
    /**
     * registerInputer
     *
     * @param inputer
     * @return boolean register success or fail
     */
    function registerInputer(inputer:IInputer) : boolean;

    /**
     * unregisterInputer
     */
    function unregisterInputer():void;

    /**
     * Password input box callback
     */
    interface IInputer{
        onGetData : (callback:IInputData)=>void
    }

    /**
     * Password data callback
     */
    interface IInputData{
        onSetData:(pinSubType:AuthSubType, data:Uint8Array)=>void
    }

    /**
     * Credential subtype: 6-digit digital password, user-defined digital password,
     * user-defined mixed password, 2D face, 3D face
     */
     enum AuthSubType{
        /**
         * Authentication sub type six number pin.
         */
        PIN_SIX = 10000,
        /**
         * Authentication sub type self defined number pin.
         */
        PIN_NUMBER = 10001,
        /**
         * Authentication sub type 2D face.
         */
        PIN_MIXED = 10002,
        /**
         * Authentication sub type 2D face.
         */
        FACE_2D = 20000,
        /**
         * Authentication sub type 3D face.
         */
        FACE_3D = 20001
    }

}