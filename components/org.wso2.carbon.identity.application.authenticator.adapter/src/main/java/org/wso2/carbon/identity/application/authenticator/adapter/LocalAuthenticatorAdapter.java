/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.adapter;

import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.common.model.LocalAuthenticatorConfig;

/**
 * This is the authenticator class to authenticate and identify user whose identity managed by the system or user
 * verification.
 */
public class LocalAuthenticatorAdapter extends AbstractAuthenticatorAdapter implements LocalApplicationAuthenticator {

    public LocalAuthenticatorAdapter(LocalAuthenticatorConfig config) {

        authenticatorName = config.getName();
        friendlyName = config.getDisplayName();
    }
}
