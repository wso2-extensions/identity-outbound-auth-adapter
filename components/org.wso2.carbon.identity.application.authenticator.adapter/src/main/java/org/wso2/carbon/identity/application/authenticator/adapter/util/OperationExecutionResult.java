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

package org.wso2.carbon.identity.application.authenticator.adapter.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.action.execution.model.PerformableOperation;
import org.wso2.carbon.identity.application.authenticator.adapter.AuthenticationResponseProcessor;

/**
 * This class represents the result of the execution of an operation.
 * It contains the operation that was executed, the status of the execution and a message.
 * This is used to summarize the operations performed based on action response.
 */
public class OperationExecutionResult {

    private static final Log LOG = LogFactory.getLog(AuthenticationResponseProcessor.class);
    private final PerformableOperation operation;
    private Status status;
    private String message;

    public OperationExecutionResult(PerformableOperation operation) {

        this.operation = operation;
    }

    public OperationExecutionResult(PerformableOperation operation, Status status, String message) {

        this.operation = operation;
        this.status = status;
        this.message = message;
    }
    public PerformableOperation getOperation() {

        return operation;
    }

    public Status getStatus() {

        return status;
    }

    public String getMessage() {

        return message;
    }

    public void setStatus(Status status) {

        this.status = status;
    }

    public void setMessage(String message) {

        this.message = message;
    }

    /**
     * Enum to represent the status of the operation execution.
     */
    public enum Status {
        SUCCESS, FAILURE, IGNORE
    }
}
