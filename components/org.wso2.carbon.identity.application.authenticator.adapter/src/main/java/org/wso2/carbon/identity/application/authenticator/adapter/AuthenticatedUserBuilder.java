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
import org.wso2.carbon.identity.action.execution.exception.ActionExecutionResponseProcessorException;
import org.wso2.carbon.identity.action.execution.model.UserStore;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.AuthenticatorAdapterDataHolder;
import org.wso2.carbon.identity.application.authenticator.adapter.model.AuthenticatingUser;
import org.wso2.carbon.identity.application.authenticator.adapter.model.UserClaim;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.HashMap;
import java.util.Map;

public class AuthenticatedUserBuilder {

    private AuthenticatedUser authenticatedUser;
    private final AuthenticatingUser user;
    
    public AuthenticatedUserBuilder(AuthenticatingUser user) {
        authenticatedUser = new AuthenticatedUser();
        this.user = user;
    }

    /**
     * Create a new authenticated user based on the executed operations.
     *
     * @throws ActionExecutionResponseProcessorException    If error occurred while creating authenticated user
     *                                                      due to invalid operation.
     * @throws UserStoreException                           If error occurred while retrieving local user details.
     */
    public AuthenticatedUser createAuthenticateduser(AuthenticatingUser user, AuthenticationContext context,
                            UserStore userStore) throws ActionExecutionResponseProcessorException, UserStoreException {

        authenticatedUser.setFederatedUser(resolveUserType());
        authenticatedUser.setUserAttributes(resolveUserClaims());

        if (authenticatedUser.isFederatedUser()) {
            authenticatedUser.setFederatedIdPName(context.getExternalIdP().getIdPName());
        } else {
            /* User ID can only be set for local users. If the user is a federated user, will be ignored.
             */
            AbstractUserStoreManager userStoreManager = resolveUserStoreManager(context, userStore.getName());
            authenticatedUser.setUserStoreDomain(userStore.getName());
            String userId = resolveUserId(userStoreManager);
            authenticatedUser.setUserId(userId);
            authenticatedUser.setUserName(userStoreManager.getUserNameFromUserID(userId));
        }
        authenticatedUser.setAuthenticatedSubjectIdentifier(
                resolveSubjectIdentifier(authenticatedUser.isFederatedUser()));
        authenticatedUser.setTenantDomain(context.getTenantDomain());

        return authenticatedUser;
    }

    /**
     * Validate and return userType. The user type has to be either LOCAL or FED, if it is not any of them or
     * not provided throw as exception.
     *
     * @return True if the user.getIdp() is FED, false if user.getIdp() is LOCAL.
     * @throws ActionExecutionResponseProcessorException If invalid user type is provided.
     */
    private boolean resolveUserType()
            throws ActionExecutionResponseProcessorException {

        if (StringUtils.equalsIgnoreCase(
                AuthenticatorAdapterConstants.AuthRequestEntityPaths.UserType.LOCAL.toString(), user.getIdp())) {
            return false;
        } else if (StringUtils.equalsIgnoreCase(
                AuthenticatorAdapterConstants.AuthRequestEntityPaths.UserType.FED.toString(), user.getIdp())) {
            return true;
        } else {
            throw new ActionExecutionResponseProcessorException("Undefined user user.getIdp() type is provided for " +
                    "the authenticated user in external authenticator service response payload: " + user.getIdp());
        }
    }

    /**
     * Validate and return the userId. Check if a user exists for the given userId.
     *
     * @return UserID for the authenticated user.
     * @throws ActionExecutionResponseProcessorException If invalid user id is provided.
     */
    private String resolveUserId(AbstractUserStoreManager userStoreManager)
            throws ActionExecutionResponseProcessorException {

        if (user.getId() == null) {
            throw new ActionExecutionResponseProcessorException("The user ID of the authenticated user in the " +
                    "external authenticator service response payload must not be null.");
        }
        try {
            if (!userStoreManager.isExistingUserWithID(user.getId())) {
                throw new ActionExecutionResponseProcessorException("No user is found for the given user id: "
                        +  user.getId());
            }
            return user.getId();
        } catch (UserStoreException e) {
            throw new ActionExecutionResponseProcessorException("An error occurs when trying to check whether user" +
                    " exist for the given user id :" +  user.getId(), e );
        }
    }

    /**
     * Validate and return subject identifier for the authenticated user.
     *
     * @return Subject Identifier for the authenticated user.
     */
    private String resolveSubjectIdentifier(boolean isFederatedUser) {

        /* Return the `user.getSub()` from the response if it is not empty. If `user.getSub()` is empty and the user is
         federated, return the external ID. If `user.getSub()` is empty and the user is local, return the user ID.
         */
        if (StringUtils.isNotBlank(user.getSub())) {
            return user.getSub();
        }
        if (isFederatedUser) {
            return user.getExternalId();
        }
        return user.getId();
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

    /**
     * Validate and return user claims.
     *
     * @return Claim mappings for the authenticated user.
     */
    public Map<ClaimMapping, String> resolveUserClaims() {

        Map<ClaimMapping, String> userAttributes = new HashMap<>();

        for (UserClaim claim : user.getUserClaims()) {
            userAttributes.put(ClaimMapping.build(
                    claim.getName(), claim.getName(), null, false), claim.getValue());
        }
        userAttributes.put(ClaimMapping.build(AuthenticatorAdapterConstants.AuthRequestEntityPaths.EXTERNAL_ID_CLAIM,
                AuthenticatorAdapterConstants.AuthRequestEntityPaths.EXTERNAL_ID_CLAIM, null, false),
                user.getExternalId());
        return userAttributes;
    }
}
