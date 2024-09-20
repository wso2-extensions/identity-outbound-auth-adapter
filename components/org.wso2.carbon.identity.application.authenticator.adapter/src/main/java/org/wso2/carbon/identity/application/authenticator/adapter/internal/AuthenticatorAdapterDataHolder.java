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

package org.wso2.carbon.identity.application.authenticator.adapter.internal;

import org.wso2.carbon.identity.action.execution.ActionExecutorService;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * Data holder for authenticator adapter component.
 */
public class AuthenticatorAdapterDataHolder {

    private static final AuthenticatorAdapterDataHolder instance = new AuthenticatorAdapterDataHolder();
    private ActionExecutorService actionExecutorService;
    private OrganizationManager organizationManager;
    private RealmService realmService;

    private AuthenticatorAdapterDataHolder() {

    }

    public static AuthenticatorAdapterDataHolder getInstance() {

        return instance;
    }

    /**
     * Get Action Executor Service instance.
     *
     * @return ActionExecutorService instance.
     */
    public ActionExecutorService getActionExecutorService() {

        return actionExecutorService;
    }

    /**
     * Set Action Executor Service instance.
     *
     * @param actionExecutorService ActionExecutorService instance.
     */
    public void setActionExecutorService(ActionExecutorService actionExecutorService) {

        this.actionExecutorService = actionExecutorService;
    }

    /**
     * Get Organization Manager instance.
     *
     * @return Organization Manager instance.
     */
    public OrganizationManager getOrganizationManager() {

        return organizationManager;
    }

    /**
     * Set Organization Manager instance.
     *
     * @param organizationManager Organization Manager instance.
     */
    public void setOrganizationManager(OrganizationManager organizationManager) {

        this.organizationManager = organizationManager;
    }

    /**
     * Get RealmService instance.
     *
     * @return RealmService instance.
     */
    public RealmService getRealmService() {

        return realmService;
    }

    /**
     * Set RealmService instance.
     *
     * @param realmService  RealmService instance.
     */
    public void setRealmService(RealmService realmService) {

        this.realmService = realmService;
    }
}
