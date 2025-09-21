package ch.luschmar.jxa.auth.server.graphql;

import graphql.execution.ExecutionId;
import graphql.execution.ExecutionIdProvider;

public class CustomExecutionIdProvider implements ExecutionIdProvider {
    @Override
    public ExecutionId provide(String query, String operationName, Object context) {
        return null;
    }
}
