package ch.luschmar.jxa.auth.server.api.reverse;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
class GraphqlSplitterControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void asdfasdfasdf() throws Exception {
        mockMvc.perform(post("/graphql").contentType(MediaType.APPLICATION_JSON).content("[{\"asd\":\"asd\"}, {\"bnm\":\"bnm\"}]")).andDo(print()).andExpect(status().isOk());
    }
}