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

import org.wso2.carbon.identity.action.execution.model.Event;
import org.wso2.carbon.identity.action.execution.model.Organization;
import org.wso2.carbon.identity.action.execution.model.Request;
import org.wso2.carbon.identity.action.execution.model.Tenant;
import org.wso2.carbon.identity.action.execution.model.User;
import org.wso2.carbon.identity.action.execution.model.UserStore;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthHistory;

/**
 * This class holds the authentication request event object which is communicated to the external
 * authentication service.
 */
public class AuthenticationRequestEvent extends Event {

    private AuthenticationRequestEvent(Builder builder) {

        int currentStepIndex = builder.currentStepIndex;
        AuthenticationRequestEvent.AuthenticatedStep[] authenticatedSteps = builder.authenticatedSteps;
        this.request = builder.request;
        this.organization = builder.organization;
        this.tenant = builder.tenant;
        this.user = builder.user;
        this.userStore = builder.userStore;
    }

    /**
     * Builder for Authentication Request Event.
     */
    public static class Builder {

        private int currentStepIndex;
        private AuthenticationRequestEvent.AuthenticatedStep[] authenticatedSteps;
        private Request request;
        private Organization organization;
        private Tenant tenant;
        private User user;
        private UserStore userStore;

        public Builder currentStepIndex(int currentStep) {

            this.currentStepIndex = currentStep;
            return this;
        }

        public Builder authenticatedSteps(AuthenticatedStep[] authenticatedSteps) {

            this.authenticatedSteps = authenticatedSteps;
            return this;
        }

        public Builder request(Request request) {

            this.request = request;
            return this;
        }

        public Builder organization(Organization organization) {

            this.organization = organization;
            return this;
        }

        public Builder tenant(Tenant tenant) {

            this.tenant = tenant;
            return this;
        }

        public Builder user(User user) {

            this.user = user;
            return this;
        }

        public Builder userStore(UserStore userStore) {

            this.userStore = userStore;
            return this;
        }

        public AuthenticationRequestEvent build() {

            return new AuthenticationRequestEvent(this);
        }
    }

    /**
     * Immutable class for Authentication step object creation.
     */
    public static class AuthenticatedStep {

        public AuthenticatedStep(int order, AuthHistory authHistory) {
            int index = order;
            String name = authHistory.getAuthenticatorName();
        }
    }
}

