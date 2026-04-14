package ee.ria.ocspcrl.logging;

import com.fasterxml.jackson.annotation.JsonInclude;
import net.logstash.logback.decorate.MapperBuilderDecorator;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.cfg.DateTimeFeature;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.util.StdDateFormat;

import java.text.DateFormat;

@Deprecated // Move to eID-Common library
public class LogbackMapperBuilderDecorator implements MapperBuilderDecorator<JsonMapper, JsonMapper.Builder> {

    @Override
    public JsonMapper.Builder decorate(JsonMapper.Builder builder) {
        return builder
                .disable(DateTimeFeature.WRITE_DATES_AS_TIMESTAMPS)
                .defaultDateFormat(new StdDateFormat().withColonInTimeZone(false))
                .changeDefaultPropertyInclusion(incl ->
                        incl.withValueInclusion(JsonInclude.Include.NON_NULL)
                                .withContentInclusion(JsonInclude.Include.NON_NULL))
                .propertyNamingStrategy(
                        PropertyNamingStrategies.SNAKE_CASE);
    }
}
