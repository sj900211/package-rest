package run.freshr.common.config;

import static ch.qos.logback.classic.Level.ALL;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.HashMap;
import net.logstash.logback.appender.LogstashTcpSocketAppender;
import net.logstash.logback.encoder.LogstashEncoder;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

@Profile({"dev", "staging", "prod"})
@Configuration
public class LogstashConfig {

  private static String activeProfile;
  private static String logstashUrl;
  private static Integer logstashPort;
  private static String logName;

  private static ObjectMapper objectMapper;

  @Autowired
  public LogstashConfig(ObjectMapper objectMapper) {
    LogstashConfig.objectMapper = objectMapper;
  }

  @Bean
  public static LoggerContext loggerContext() {
    return (LoggerContext) LoggerFactory.getILoggerFactory();
  }

  @Bean(initMethod="start", destroyMethod="stop")
  public static LogstashTcpSocketAppender logstashTcpSocketAppender(LoggerContext context)
      throws JsonProcessingException {
    LogstashTcpSocketAppender logstashTcpSocketAppender = new LogstashTcpSocketAppender();
    LogstashEncoder logstashEncoder = new LogstashEncoder();
    HashMap<String, String> map = new HashMap<>();

    map.put("name", logName);
    map.put("profile", activeProfile);

    logstashEncoder.setCustomFields(objectMapper.writeValueAsString(map));

    logstashTcpSocketAppender.addDestination(logstashUrl + ":" + logstashPort);
    logstashTcpSocketAppender.setEncoder(logstashEncoder);
    logstashTcpSocketAppender.setContext(context);

    return logstashTcpSocketAppender;
  }

  @Bean
  public static Logger registerSpringLogger(LoggerContext loggerContext,
      LogstashTcpSocketAppender logstashTcpSocketAppender) {
    Logger logger = loggerContext.getLogger("org.springframework");

    logger.setLevel(ALL);
    logger.addAppender(logstashTcpSocketAppender);

    return logger;
  }

  @Value("${spring.profiles.active}")
  public void setActiveProfile(String activeProfile) {
    LogstashConfig.activeProfile = activeProfile;
  }

  @Value("${freshr.logstash.url}")
  public void setLogstashUrl(String logstashUrl) {
    LogstashConfig.logstashUrl = logstashUrl;
  }

  @Value("${freshr.logstash.port}")
  public void setLogstashPort(Integer logstashPort) {
    LogstashConfig.logstashPort = logstashPort;
  }

  @Value("${ELK_LOG_NAME}")
  public void setLogName(String logName) {
    LogstashConfig.logName = logName;
  }

}
