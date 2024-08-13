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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.action.execution.exception.ActionExecutionRequestBuilderException;
import org.wso2.carbon.identity.action.execution.exception.ActionExecutionResponseProcessorException;
import org.wso2.carbon.identity.action.execution.model.ActionExecutionRequest;
import org.wso2.carbon.identity.action.execution.model.ActionExecutionStatus;
import org.wso2.carbon.identity.action.execution.model.ActionInvocationSuccessResponse;
import org.wso2.carbon.identity.action.execution.model.Operation;
import org.wso2.carbon.identity.action.execution.model.PerformableOperation;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.Property;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This class holds the external custom authentication.
 */
public class AuthenticatorAdapter extends AbstractApplicationAuthenticator implements FederatedApplicationAuthenticator {

    private static final Log log = LogFactory.getLog(AuthenticatorAdapter.class);

    @Override
    public boolean canHandle(HttpServletRequest request) {

        return false;
    }

    @Override
    public FrameworkConstants.AuthenticatorType getAuthenticatorType() {

        return FrameworkConstants.AuthenticatorType.CUSTOM;
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {

        if (context.isLogoutRequest()){
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        }

        Map<String, Object> eventContext = new HashMap<>();
        eventContext.put(AuthenticatorAdapterConstants.AUTH_REQUEST, request);
        eventContext.put(AuthenticatorAdapterConstants.AUTH_CONTEXT, context);
        eventContext.put(AuthenticatorAdapterConstants.FLOW_ID, getContextIdentifier(request));

        // TODO: Execute action framework to send the authentication request and the return processed response.
    }

    @Override
    public String getFriendlyName() {

        return AuthenticatorAdapterConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getName() {

        return AuthenticatorAdapterConstants.AUTHENTICATOR_NAME;
    }

    @Override
    public String getClaimDialectURI() {

        return AuthenticatorAdapterConstants.WSO2_CLAIM_DIALECT ;
    }

    @Override
    public List<Property> getConfigurationProperties() {

        // Todo: resolve authenticator configuration with the Action feature.
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        throw new UnsupportedOperationException();
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        throw new UnsupportedOperationException();
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        // TODO: Resolve context identifier which will be used as the flow id.
    }

    @Override
    public String getI18nKey() {

        return AuthenticatorAdapterConstants.AUTHENTICATOR_NAME;
    }
}