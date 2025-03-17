package ch.luschmar.jxa.hawk;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.http.HttpHeaders.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {
        "org.springframework.web.servlet.mvc.method.annotation: DEBUG"
})
@AutoConfigureMockMvc
class HawkWebTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void exampleWithoutPayload_ok() throws Exception {
        mockMvc.perform(get("/resource/1?b=1&a=2").header(HOST, "example.com:8000")
                        .header(AUTHORIZATION, "Hawk " +
                                "id=\"dh37fgj492je\", " +
                                "ts=\"1353832234\", " +
                                "nonce=\"j4h3g2\", " +
                                "ext=\"some-app-ext-data\", " +
                                "mac=\"6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE=\""))
                .andDo(print()).andExpect(status().isOk())
                .andExpect(content().string(containsString("Hello, World")));
    }

    @Test
    void exampleWithPayload_ok() throws Exception {
        mockMvc.perform(post("/resource/1?b=1&a=2").header(HOST, "example.com:8000")
                        .header(AUTHORIZATION, "Hawk " +
                                "id=\"dh37fgj492je\", " +
                                "ts=\"1353832234\", " +
                                "nonce=\"j4h3g2\", " +
                                "hash=\"Yi9LfIIFRtBEPt74PVmbTF/xVAwPn7ub15ePICfgnuY=\", " +
                                "ext=\"some-app-ext-data\", " +
                                "mac=\"aSe1DERmZuRl3pI36/9BdZmnErTw3sNzOOAUlfeKjVw=\"")
                        .header(CONTENT_TYPE, "text/plain").content("Thank you for flying Hawk"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Hello, World")));
    }
}
