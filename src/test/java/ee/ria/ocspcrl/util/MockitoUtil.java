package ee.ria.ocspcrl.util;

import lombok.experimental.UtilityClass;
import org.mockito.stubbing.Answer;

@UtilityClass
public class MockitoUtil {

    public static final Answer<?> ANSWER_THROW_EXCEPTION = invocation -> {
        throw new IllegalStateException("Unexpected method invocation: " + invocation);
    };

}
