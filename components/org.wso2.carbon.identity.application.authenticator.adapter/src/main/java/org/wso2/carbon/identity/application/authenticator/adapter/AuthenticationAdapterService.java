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

import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.LocalAuthenticatorConfig;

/**
 * This is the service class for handling the Authenticator Adapters.
 */
public class AuthenticationAdapterService {

    /**
     * Create nre Federated Authenticator Adapter for given configurations.
     *
     * @param config    Federated Authenticator Configuration.
     * @return  FederatedAuthenticatorAdapter instance.
     */
    public ApplicationAuthenticator createFederatedAuthenticatorAdapter(FederatedAuthenticatorConfig config) {

        return new FederatedAuthenticatorAdapter(config);
    }

    /**
     * Create nre local Authenticator Adapter for given configurations.
     *
     * @param config    Local Authenticator Configuration.
     * @return  LocalAuthenticatorAdapter instance.
     */
    public ApplicationAuthenticator createLocalAuthenticatorAdapter(LocalAuthenticatorConfig config) {

        return new LocalAuthenticatorAdapter(config);
    }
}
