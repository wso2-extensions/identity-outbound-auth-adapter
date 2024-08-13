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

import org.wso2.carbon.identity.action.execution.model.Request;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This class holds the authentication request object which is communicated to the external authentication service.
 */
public class AuthenticationRequest extends Request {

    private static final List<String> headersToAvoid = new ArrayList<>();
    private static final List<String> paramsToAvoid = new ArrayList<>();

    static {
        headersToAvoid.add("authorization");
        headersToAvoid.add("cookie");
        headersToAvoid.add("set-cookie");
        headersToAvoid.add("accept-encoding");
        headersToAvoid.add("accept-language");
        headersToAvoid.add("content-length");
        headersToAvoid.add("content-type");
        // parameters from authorization code grant
        paramsToAvoid.add("code");
        paramsToAvoid.add("redirect_uri");
        paramsToAvoid.add("grant_type");
        paramsToAvoid.add("scope");
        // parameters from password grant
        paramsToAvoid.add("username");
        paramsToAvoid.add("password");
        // parameters from refresh token grant
        paramsToAvoid.add("refresh_token");
        // parameters used for client authentication for token endpoint
        paramsToAvoid.add("client_id");
        paramsToAvoid.add("client_secret");
        paramsToAvoid.add("client_assertion_type");
        paramsToAvoid.add("client_assertion");
    }

    private AuthenticationRequest(Builder builder) {

        this.additionalHeaders = builder.additionalHeaders;
        this.additionalParams = builder.additionalParams;
    }

    /**
     * Builder for Authentication Request.
     */
    public static class Builder {

        private final Map<String, String[]> additionalHeaders = new HashMap<>();
        private final Map<String, String[]> additionalParams = new HashMap<>();

        public Builder addAdditionalHeader(String key, String[] value) {

            if (!headersToAvoid.contains(key.toLowerCase())) {
                this.additionalHeaders.put(key, value);
            }
            return this;
        }

        public Builder addAdditionalParam(String key, String[] value) {

            if (!paramsToAvoid.contains(key)) {
                this.additionalParams.put(key, value);
            }
            return this;
        }

        public AuthenticationRequest build() {

            return new AuthenticationRequest(this);
        }
    }
}
