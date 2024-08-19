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

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.action.execution.ActionExecutionResponseProcessor;
import org.wso2.carbon.identity.action.execution.exception.ActionExecutionResponseProcessorException;
import org.wso2.carbon.identity.action.execution.model.ActionExecutionStatus;
import org.wso2.carbon.identity.action.execution.model.ActionInvocationErrorResponse;
import org.wso2.carbon.identity.action.execution.model.ActionInvocationResponse;
import org.wso2.carbon.identity.action.execution.model.ActionInvocationSuccessResponse;
import org.wso2.carbon.identity.action.execution.model.ActionType;
import org.wso2.carbon.identity.action.execution.model.Event;
import org.wso2.carbon.identity.action.execution.model.PerformableOperation;
import org.wso2.carbon.identity.action.execution.model.UserStore;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authenticator.adapter.model.AuthenticatingUser;
import org.wso2.carbon.identity.application.authenticator.adapter.model.UserClaim;
import org.wso2.carbon.user.api.UserStoreException;

import java.util.List;
import java.util.Map;

/**
 * This is responsible for processing authentication response from the external authentication service.
 */
public class AuthenticationResponseProcessor implements ActionExecutionResponseProcessor {

    private static final Log LOG = LogFactory.getLog(AuthenticationResponseProcessor.class);
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public ActionType getSupportedActionType() {

        return ActionType.AUTHENTICATION;
    }

    @Override
    public ActionExecutionStatus processSuccessResponse(Map<String, Object> eventContext, Event event,
                                                        ActionInvocationSuccessResponse actionInvocationSuccessResponse)
            throws ActionExecutionResponseProcessorException {

        AuthenticationContext context = (AuthenticationContext) eventContext.get(
                AuthenticatorAdapterConstants.AUTH_CONTEXT);
        ActionInvocationResponse.Status actionStatus = actionInvocationSuccessResponse.getActionStatus();

        if (ActionInvocationResponse.Status.SUCCESS.equals(actionStatus)) {
            List<PerformableOperation> operationsToPerform = actionInvocationSuccessResponse.getOperations();
            try {
                AuthenticatingUser authenticatingUser = new AuthenticatingUser(StringUtils.EMPTY);
                UserStore userStore = new UserStore(StringUtils.EMPTY);
                if (operationsToPerform != null) {
                    for (PerformableOperation operation : operationsToPerform) {
                        performOperation(operation, authenticatingUser, userStore);
                    }
                }
                AuthenticatedUserBuilder authenticatedUserBuilder = new AuthenticatedUserBuilder(authenticatingUser);
                context.setSubject(authenticatedUserBuilder.createAuthenticateduser(
                        authenticatingUser, context, userStore));
            } catch (UserStoreException e) {
                throw new ActionExecutionResponseProcessorException("Error occurred when trying to build authenticated " +
                        "user from the external authenticator service response." ,e);
            }
        }

        // TODO: Log operation process results.
        return new ActionExecutionStatus(ActionExecutionStatus.Status.SUCCESS, eventContext);
    }

    @Override
    public ActionExecutionStatus processErrorResponse(Map<String, Object> eventContext,
                                                      Event actionEvent,
                                                      ActionInvocationErrorResponse errorResponse) throws
            ActionExecutionResponseProcessorException {

        return new ActionExecutionStatus(ActionExecutionStatus.Status.ERROR, eventContext);
    }

    /**
     * Validate the given performableOperation and apply it to the user attribute.
     *
     * @param performableOperation  PerformableOperation from the external authentication service response.
     */
    private void performOperation(PerformableOperation performableOperation, AuthenticatingUser authRequestUser,
                                  UserStore userStoreDomain) throws ActionExecutionResponseProcessorException {

        switch (performableOperation.getPath()) {
            case AuthenticatorAdapterConstants.AuthRequestEntityPaths.USER_ID_PATH:
                authRequestUser.setId(castToString(performableOperation.getValue()));
                break;
            case AuthenticatorAdapterConstants.AuthRequestEntityPaths.EXTERNAL_ID_PATH:
                authRequestUser.setExternalId(castToString(performableOperation.getValue()));
                break;
            case AuthenticatorAdapterConstants.AuthRequestEntityPaths.IDP_PATH:
                authRequestUser.setIdp(castToString(performableOperation.getValue()));
                break;
            case AuthenticatorAdapterConstants.AuthRequestEntityPaths.SUB_PATH:
                authRequestUser.setSub(castToString(performableOperation.getValue()));
                break;
            case AuthenticatorAdapterConstants.AuthRequestEntityPaths.USER_CLAIM_PATH:
                authRequestUser.setUserClaims(castToClaim(performableOperation.getValue()));
                break;
            case AuthenticatorAdapterConstants.AuthRequestEntityPaths.USER_STORE_NAME_PATH:
                userStoreDomain.setName(castToString(performableOperation.getValue()));
                break;
            default:
                break;
        }
    }

    /**
     * Cast the given object to String.
     *
     * @param object    Object that need to cast.
     * @return String which cast to the String class.
     * @throws ActionExecutionResponseProcessorException If object cannot be cast to String.
     */
    private String castToString(Object object)
            throws ActionExecutionResponseProcessorException {

        try {
            return objectMapper.convertValue(object, String.class);
        } catch (IllegalArgumentException e) {
            throw new ActionExecutionResponseProcessorException("The provided value cannot be cast to a string:" +
                    object, e);
        }
    }

    /**
     * Cast the given object to a claim.
     *
     * @param object    Object that need to cast.
     * @return userClaim which casted to the UserClaim class.
     */
    private UserClaim castToClaim(Object object) {

        try {
            return objectMapper.convertValue(object, UserClaim.class);
        } catch (IllegalArgumentException e) {
            // Not throwing an error and ignore as this is just a claim.
            return null;
        }
    }
}

