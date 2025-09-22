package ch.luschmar.jxa.auth.server.api.reverse;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class WrappedGraphQlRequest {
    private final String request;

    @JsonCreator(mode = JsonCreator.Mode.DELEGATING)
    public WrappedGraphQlRequest(Object obj) {
        try {
            request = new ObjectMapper().writeValueAsString(obj);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Error deserializing MyDataObject", e);
        }
    }

    public String body() {
        return request;
    }
}
