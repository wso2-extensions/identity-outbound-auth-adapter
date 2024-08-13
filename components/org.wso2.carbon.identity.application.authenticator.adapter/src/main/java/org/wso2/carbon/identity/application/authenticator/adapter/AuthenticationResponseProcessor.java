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
import org.wso2.carbon.identity.action.execution.model.Operation;
import org.wso2.carbon.identity.action.execution.model.PerformableOperation;
import org.wso2.carbon.identity.action.execution.model.UserStore;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.AuthenticatorAdapterDataHolder;
import org.wso2.carbon.identity.application.authenticator.adapter.model.AuthenticationRequestUser;
import org.wso2.carbon.identity.application.authenticator.adapter.model.UserClaim;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;

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
                AuthenticationRequestUser authRequestUser = new AuthenticationRequestUser(StringUtils.EMPTY);
                UserStore userStore = new UserStore(StringUtils.EMPTY);
                if (operationsToPerform != null) {
                    for (PerformableOperation operation : operationsToPerform) {
                        performOperation(operation, authRequestUser, userStore);
                    }
                }
                context.setSubject(createAuthenticateduser(authRequestUser, context, userStore));
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
    public void performOperation(PerformableOperation performableOperation, AuthenticationRequestUser authRequestUser,
                                 UserStore userStoreDomain) throws ActionExecutionResponseProcessorException {

        if (!isAllowedOperation(performableOperation.getOp())) {
            return;
        }

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
     * Only the REPLACE operation is allowed. If any other operation is provided, it will be ignored
     * and the authenticated user will not be updated.
     *
     * @param operation Operation from the external authentication service response.
     */
    private boolean isAllowedOperation(Operation operation) {

        return Operation.REPLACE.equals(operation);
    }

    /**
     * Create a new authenticated user based on the executed operations.
     *
     * @throws ActionExecutionResponseProcessorException    If error occurred while creating authenticated user
     *                                                      due to invalid operation.
     * @throws UserStoreException                           If error occurred while retrieving local user details.
     */
    public AuthenticatedUser createAuthenticateduser(AuthenticationRequestUser user, AuthenticationContext context,
            UserStore userStore) throws ActionExecutionResponseProcessorException, UserStoreException {

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setFederatedUser(user.resolveUserType());
        authenticatedUser.setUserAttributes(user.resolveUserClaims());

        if (authenticatedUser.isFederatedUser()) {
            authenticatedUser.setFederatedIdPName(context.getExternalIdP().getIdPName());
        } else {
            /* User ID can only be set for local users. If the user is a federated user, will be ignored.
             */
            AbstractUserStoreManager userStoreManager = resolveUserStoreManager(context, userStore.getName());
            authenticatedUser.setUserStoreDomain(userStore.getName());
            String userId = user.resolveUserId(userStoreManager);
            authenticatedUser.setUserId(userId);
            authenticatedUser.setUserName(userStoreManager.getUserNameFromUserID(userId));
        }
        authenticatedUser.setAuthenticatedSubjectIdentifier(
                user.resolveSubjectIdentifier(authenticatedUser.isFederatedUser()));
        authenticatedUser.setTenantDomain(context.getTenantDomain());

        return authenticatedUser;
    }

    /**
     * Cast the given object to String.
     * @param object    Object that need to cast.
     *
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
     * @param object    Object that need to cast.
     *
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

    private AbstractUserStoreManager resolveUserStoreManager(AuthenticationContext context, String userStoreDomain)
            throws ActionExecutionResponseProcessorException {

        AbstractUserStoreManager userStoreManager;
        try {
            RealmService realmService = AuthenticatorAdapterDataHolder.getInstance().getRealmService();
            int tenantId = realmService.getTenantManager().getTenantId(context.getTenantDomain());
            UserRealm userRealm = (UserRealm) realmService.getTenantUserRealm(tenantId);
            if (IdentityUtil.getPrimaryDomainName().equals(userStoreDomain)) {
                userStoreManager = (AbstractUserStoreManager) userRealm.getUserStoreManager();
            } else {
                userStoreManager = (AbstractUserStoreManager) userRealm.getUserStoreManager()
                        .getSecondaryUserStoreManager(userStoreDomain);
            }
        } catch (UserStoreException e) {
            throw new ActionExecutionResponseProcessorException("An error occurs when trying to retrieve the userStore "
                    +  "manager for the given userStore domain name:" +  userStoreDomain, e );
        }

        if (userStoreManager == null) {
            throw new ActionExecutionResponseProcessorException("No userStore is found for the given userStore " +
                    "domain name: " + userStoreDomain);
        }

        return userStoreManager;
    }

}

