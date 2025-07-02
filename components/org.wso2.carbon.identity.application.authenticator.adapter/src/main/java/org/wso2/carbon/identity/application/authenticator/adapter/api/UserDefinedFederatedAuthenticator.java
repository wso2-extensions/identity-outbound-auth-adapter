/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.application.authenticator.adapter.api;

import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.AbstractAuthenticatorAdapter;
import org.wso2.carbon.identity.application.common.model.UserDefinedFederatedAuthenticatorConfig;

import java.util.Optional;

import javax.servlet.http.HttpServletRequest;

/**
 * This is the authenticator class to authenticate and identify user whose identity managed externally.
 */
public class UserDefinedFederatedAuthenticator extends AbstractAuthenticatorAdapter implements
        FederatedApplicationAuthenticator {

    private static final long serialVersionUID = 2468013579246801357L;

    @Override
    public boolean isAPIBasedAuthenticationSupported() {

        return true;
    }

    @Override
    public Optional<AuthenticatorData> getAuthInitiationData(AuthenticationContext context)
            throws AuthenticationFailedException {

        return super.getAuthInitiationData(context);
    }

    @Override
    public boolean isSatisfyAuthenticatorPrerequisites(HttpServletRequest request, AuthenticationContext context)
            throws AuthenticationFailedException {

        return super.isSatisfyAuthenticatorPrerequisites(request, context);
    }

    @Override
    public boolean canHandleRequestFromMultiOptionStep(HttpServletRequest request, AuthenticationContext context) {

        return super.canHandleRequestFromMultiOptionStep(request, context);
    }



    public UserDefinedFederatedAuthenticator(UserDefinedFederatedAuthenticatorConfig config) {

        authenticatorName = config.getName();
        friendlyName = config.getDisplayName();
    }
}
