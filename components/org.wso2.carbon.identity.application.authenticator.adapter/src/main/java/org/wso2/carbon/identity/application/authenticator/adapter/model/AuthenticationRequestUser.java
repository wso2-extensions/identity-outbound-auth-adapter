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

package org.wso2.carbon.identity.application.authenticator.adapter.model;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.action.execution.exception.ActionExecutionResponseProcessorException;
import org.wso2.carbon.identity.action.execution.model.User;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.adapter.AuthenticatorAdapterConstants;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This class holds the authenticated user object which is communicated to the external authentication service.
 */
public class AuthenticationRequestUser extends User {

    private String idp;
    private String sub;
    private String externalId;
    private final List<UserClaim> userClaims =  new ArrayList<>();

    public AuthenticationRequestUser(String id){

        super(id);
    }

    public AuthenticationRequestUser(String id, AuthenticatedUser user) {

        super(id);
        sub = user.getAuthenticatedSubjectIdentifier();

        Map<ClaimMapping, String> userAttributes = user.getUserAttributes();
        if (userAttributes != null) {
            for (ClaimMapping claimMap : userAttributes.keySet()) {
                String claimUri = claimMap.getLocalClaim().getClaimUri();
                if (AuthenticatorAdapterConstants.AuthRequestEntityPaths.EXTERNAL_ID_CLAIM.equals(claimUri)) {
                    externalId = userAttributes.get(claimMap);
                    break;
                }
                userClaims.add(new UserClaim(claimUri, userAttributes.get(claimMap)));
            }
        }
    }

    public void setIdp(String idp) {
        this.idp = idp;
    }

    public void setSub(String sub) {
        this.sub = sub;
    }

    public void setExternalId(String externalId) {
        this.externalId = externalId;
    }

    public void setUserClaims(UserClaim userClaim) {
        userClaims.add(userClaim);
    }

    /**
     * Validate and return userType. The user type has to be either LOCAL or FED, if it is not any of them or
     * not provided throw as exception.
     *
     * @return True if the idp is FED, false if idp is LOCAL.
     * @throws ActionExecutionResponseProcessorException If invalid user type is provided.
     */
    public boolean resolveUserType()
            throws ActionExecutionResponseProcessorException {

        if (StringUtils.equalsIgnoreCase(
                AuthenticatorAdapterConstants.AuthRequestEntityPaths.UserType.LOCAL.toString(), idp)) {
            return false;
        } else if (StringUtils.equalsIgnoreCase(
                AuthenticatorAdapterConstants.AuthRequestEntityPaths.UserType.FED.toString(), idp)) {
            return true;
        } else {
            throw new ActionExecutionResponseProcessorException("Undefined user idp type is provided for the " +
                    "authenticated user in external authenticator service response payload: " + idp);
        }
    }

    /**
     * Validate and return the userId. Check if a user exists for the given userId.
     *
     * @return UserID for the authenticated user.
     * @throws ActionExecutionResponseProcessorException If invalid user id is provided.
     */
    public String resolveUserId(AbstractUserStoreManager userStoreManager)
            throws ActionExecutionResponseProcessorException {

        if (this.getId() == null) {
            throw new ActionExecutionResponseProcessorException("The user ID of the authenticated user in the " +
                    "external authenticator service response payload must not be null.");
        }
        try {
            if (!userStoreManager.isExistingUserWithID(this.getId())) {
                throw new ActionExecutionResponseProcessorException("No user is found for the given user id: "
                        +  this.getId());
            }
            return this.getId();
        } catch (UserStoreException e) {
            throw new ActionExecutionResponseProcessorException("An error occurs when trying to check whether user" +
                    " exist for the given user id :" +  this.getId(), e );
        }
    }

    /**
     * Validate and return subject identifier for the authenticated user.
     *
     * @return Subject Identifier for the authenticated user.
     */
    public String resolveSubjectIdentifier(boolean isFederatedUser) {

        /* Return the `sub` from the response if it is not empty. If `sub` is empty and the user is federated,
         return the external ID. If `sub` is empty and the user is local, return the user ID.
         */
        if (StringUtils.isNotBlank(sub)) {
            return sub;
        }
        if (isFederatedUser) {
            return externalId;
        }
        return this.getId();
    }

    /**
     * Validate and return user claims.
     *
     * @return Claim mappings for the authenticated user.
     */
    public Map<ClaimMapping, String> resolveUserClaims() {

        Map<ClaimMapping, String> userAttributes = new HashMap<>();

        for (UserClaim claim : userClaims) {
            userAttributes.put(ClaimMapping.build(
                    claim.getName(), claim.getName(), null, false), claim.getValue());
        }
        userAttributes.put(ClaimMapping.build(AuthenticatorAdapterConstants.AuthRequestEntityPaths.EXTERNAL_ID_CLAIM,
                AuthenticatorAdapterConstants.AuthRequestEntityPaths.EXTERNAL_ID_CLAIM, null, false), externalId);
        return userAttributes;
    }
}
