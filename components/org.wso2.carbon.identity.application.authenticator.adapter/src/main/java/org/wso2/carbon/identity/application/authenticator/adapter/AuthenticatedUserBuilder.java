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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.action.execution.exception.ActionExecutionResponseProcessorException;
import org.wso2.carbon.identity.action.execution.model.UserStore;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.AuthenticatorAdapterDataHolder;
import org.wso2.carbon.identity.application.authenticator.adapter.model.AuthenticatingUser;
import org.wso2.carbon.identity.application.authenticator.adapter.model.UserClaim;
import org.wso2.carbon.identity.application.authenticator.adapter.util.OperationExecutionResult;
import org.wso2.carbon.identity.application.authenticator.adapter.util.OperationExecutionResult.Status;
import org.wso2.carbon.identity.application.authenticator.adapter.AuthenticatorAdapterConstants.AuthRequestEntityPaths;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.HashMap;
import java.util.Map;

public class AuthenticatedUserBuilder {

    private static final Log LOG = LogFactory.getLog(AuthenticatedUserBuilder.class);
    private final AuthenticatedUser authenticatedUser;
    private Map<String,OperationExecutionResult> operationExecutionResult;
    private AuthenticatingUser user;
    
    public AuthenticatedUserBuilder() {

        authenticatedUser = new AuthenticatedUser();
    }

    public void setAuthenticatingUser(AuthenticatingUser user) {

        this.user = user;
    }

    public void setOperationExecutionResult(Map<String,OperationExecutionResult> operationExecutionResult) {

        this.operationExecutionResult = operationExecutionResult;
    }

    public Map<String,OperationExecutionResult> getOperationExecutionResult() {
        return operationExecutionResult;
    }

    /**
     * Create a new authenticated user based on the executed operations.
     *
     * @throws ActionExecutionResponseProcessorException    If error occurred while creating authenticated user
     *                                                      due to invalid operation.
     * @throws UserStoreException                           If error occurred while retrieving local user details.
     */
    public AuthenticatedUser createAuthenticateduser(AuthenticatingUser user, AuthenticationContext context,
                            UserStore userStore) throws ActionExecutionResponseProcessorException {

        authenticatedUser.setFederatedUser(resolveUserType());
        if (authenticatedUser.isFederatedUser()) {
            authenticatedUser.setFederatedIdPName(context.getExternalIdP().getIdPName());
        } else {
            // User ID, userStore and username set for local users. If the user is a federated user, will be ignored.
            authenticatedUser.setUserId(user.getId());
            User localUser = resolveLocalUser(context, userStore);
            authenticatedUser.setUserStoreDomain(localUser.getUserStoreDomain());
            authenticatedUser.setUserName(localUser.getUsername());
        }
        authenticatedUser.setAuthenticatedSubjectIdentifier(
                resolveSubjectIdentifier(authenticatedUser.isFederatedUser()));
        authenticatedUser.setTenantDomain(context.getTenantDomain());
        authenticatedUser.setUserAttributes(resolveUserClaims());
        updateIgnoredOperationResults();

        return authenticatedUser;
    }

    private boolean resolveUserType()
            throws ActionExecutionResponseProcessorException {

        /* Validate and return userType. The user type has to be either LOCAL or FED, if it is not any of them or
         not provided throw as exception.*/
        if (StringUtils.equalsIgnoreCase(AuthRequestEntityPaths.UserType.LOCAL.toString(), user.getIdp())) {
            addOperationResult(AuthRequestEntityPaths.IDP_PATH, Status.SUCCESS, "User is identified as a local user.");
            return false;
        } else if (StringUtils.equalsIgnoreCase( AuthRequestEntityPaths.UserType.FED.toString(), user.getIdp())) {
            addOperationResult(AuthRequestEntityPaths.IDP_PATH, Status.SUCCESS, "User is identified as a " +
                    "federated user.");
            return true;
        } else {
            String errorMessage = "Invalid user type is provided for the authenticated user in external " +
                    "authenticator service response payload: " + user.getIdp();
            addOperationResult(AuthRequestEntityPaths.IDP_PATH, Status.SUCCESS, errorMessage);
            throw new ActionExecutionResponseProcessorException(errorMessage);
        }
    }

    private User resolveLocalUser(AuthenticationContext context, UserStore userStore)
            throws ActionExecutionResponseProcessorException {

        AbstractUserStoreManager userStoreManager = resolveUserStoreManager(context, userStore.getName());
        try {
            User resolvedUser = userStoreManager.getUser(authenticatedUser.getUserId(), null);
            addOperationResult(AuthRequestEntityPaths.USER_ID_PATH, Status.SUCCESS, "Authenticated local user " +
                    "resolved by the userId: " + user.getId());
            return resolvedUser;

        } catch (org.wso2.carbon.user.core.UserStoreException e) {
            String message = "Error occurred when trying to resolve local user by user Id:" + user.getId();
            addOperationResult(AuthRequestEntityPaths.USER_ID_PATH, Status.FAILURE, message);
            throw new ActionExecutionResponseProcessorException(message, e);

        } catch (UserIdNotFoundException e) {
            String message = "No user found for the given user Id:" + user.getId();
            addOperationResult(AuthRequestEntityPaths.USER_ID_PATH, Status.FAILURE, message);
            throw new ActionExecutionResponseProcessorException(message, e);
        }
    }

    private String resolveSubjectIdentifier(boolean isFederatedUser) {

        /* Return the `user.getSub()` from the response if it is not empty. If `user.getSub()` is empty and the user is
         federated, return the external ID. If `user.getSub()` is empty and the user is local, return the user ID.
         */
        if (StringUtils.isNotBlank(user.getSub())) {
            addOperationResult(AuthRequestEntityPaths.SUB_PATH, Status.SUCCESS, "Subject identifier of the user" +
                    " will be " + user.getSub());
            return user.getSub();
        }
        if (isFederatedUser) {
            LOG.debug("Given external Id is considered as the subject identifier of the federated user.");
            return user.getExternalId();
        }
        LOG.debug("Given user Id is considered as the subject identifier of the local user.");
        return user.getId();
    }

    private Map<ClaimMapping, String> resolveUserClaims() {

        Map<ClaimMapping, String> userAttributes = new HashMap<>();

        for (UserClaim claim : user.getUserClaims()) {
            userAttributes.put(ClaimMapping.build(
                    claim.getName(), claim.getName(), null, false), claim.getValue());
            addOperationResult(AuthRequestEntityPaths.USER_CLAIM_PATH, Status.SUCCESS, "Add the claim to the " +
                    "user claim list" + claim.getName());
        }
        userAttributes.put(ClaimMapping.build(AuthenticatorAdapterConstants.AuthRequestEntityPaths.EXTERNAL_ID_CLAIM,
                        AuthenticatorAdapterConstants.AuthRequestEntityPaths.EXTERNAL_ID_CLAIM, null, false),
                user.getExternalId());
        return userAttributes;
    }

    private AbstractUserStoreManager resolveUserStoreManager(AuthenticationContext context, String userStoreDomain)
            throws ActionExecutionResponseProcessorException {

        AbstractUserStoreManager userStoreManager;

        try {
            RealmService realmService = AuthenticatorAdapterDataHolder.getInstance().getRealmService();
            int tenantId = realmService.getTenantManager().getTenantId(context.getTenantDomain());
            UserRealm userRealm = (UserRealm) realmService.getTenantUserRealm(tenantId);
            if (StringUtils.isNotBlank(userStoreDomain)) {
                userStoreManager = (AbstractUserStoreManager) userRealm.getUserStoreManager()
                        .getSecondaryUserStoreManager(userStoreDomain);
                addOperationResult(AuthRequestEntityPaths.USER_STORE_NAME_PATH, Status.SUCCESS, "User store " +
                        "domain of the local user is set as " + userStoreDomain);
            } else {
                userStoreManager = (AbstractUserStoreManager) userRealm.getUserStoreManager();
            }
        } catch (UserStoreException e) {
            throw new ActionExecutionResponseProcessorException("An error occurs when trying to retrieve the " +
                    "userStore manager for the given userStore domain name:" +  userStoreDomain, e );
        }

        if (StringUtils.isNotBlank(userStoreDomain) && userStoreManager == null) {
            String errorMessage = "No userStore is found for the given userStore domain name: " + userStoreDomain;
            addOperationResult(AuthRequestEntityPaths.USER_STORE_NAME_PATH, Status.FAILURE, errorMessage);
            throw new ActionExecutionResponseProcessorException(errorMessage);
        }

        return userStoreManager;
    }

    private void addOperationResult(String path, OperationExecutionResult.Status status, String message) {

        OperationExecutionResult result = operationExecutionResult.get(path);
        result.setStatus(status);
        result.setMessage(message);
    }

    private void updateIgnoredOperationResults() {

        /* Update the operation result to IGNORED state, it any state is not set yet (which means operation is not
         performed.*/
        for (String entryKey: operationExecutionResult.keySet() ) {
            OperationExecutionResult result = operationExecutionResult.get(entryKey);
            if (result.getStatus() == null) {
                result.setStatus(Status.IGNORE);
                result.setMessage("Operation is not performed on the authenticated user.");
            }
        }
    }
}
