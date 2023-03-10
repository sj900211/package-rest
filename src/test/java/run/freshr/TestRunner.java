package run.freshr;

import static org.springframework.util.MimeTypeUtils.IMAGE_PNG_VALUE;
import static run.freshr.domain.auth.enumeration.Privilege.MANAGER_MAJOR;
import static run.freshr.domain.auth.enumeration.Privilege.MANAGER_MINOR;
import static run.freshr.domain.auth.enumeration.Privilege.STAFF_MAJOR;
import static run.freshr.domain.auth.enumeration.Privilege.STAFF_MINOR;
import static run.freshr.domain.auth.enumeration.Privilege.USER;

import io.minio.errors.ErrorResponseException;
import io.minio.errors.InsufficientDataException;
import io.minio.errors.InternalException;
import io.minio.errors.InvalidResponseException;
import io.minio.errors.ServerException;
import io.minio.errors.XmlParserException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import run.freshr.common.security.TokenProvider;
import run.freshr.domain.auth.entity.Manager;
import run.freshr.domain.community.enumeration.BoardNoticeExpose;
import run.freshr.service.MinioService;
import run.freshr.service.TestService;
import run.freshr.utils.StringUtil;

/**
 * Test runner.
 *
 * @author FreshR
 * @apiNote Application Run 마지막에 동작하는 Class<br>
 * Test 코드가 실행되기 전에 동작한다.
 * @since 2023. 1. 13. 오전 11:25:09
 */
@Slf4j
@Component
@Profile("test")
public class TestRunner implements ApplicationRunner {

  public static long managerMajorId;
  public static long managerMinorId;
  public static long staffMajorId;
  public static long staffMinorId;
  public static long userId;
  public static List<Long> attachIdList = new ArrayList<>();
  public static List<Long> noticeIdList = new ArrayList<>();

  @Autowired
  private TestService service;
  @Autowired
  private MinioService minioService;

  /**
   * Run.
   *
   * @param args args
   * @apiNote Test 코드는 크게 Given, When, Then 영역으로 나눌 수 있다.<br>
   * Given 영역은 테스트 데이터를 설정하는 부분인데<br>
   * Entity 구조가 복잡해질수록, 참조하는 데이터가 많아질수록<br>
   * Given 영역 코드가 점점 많아진다.<br>
   * 그리고 테스트마다 데이터를 설정하기 때문에 중복 코드도 많아진다.<br>
   * 그러다보니 관리 포인트가 점점 증가하게 되었다.<br>
   * 이 부분을 해결하고자 테스트 코드가 실행하기 전에 기본적인 데이터를 설정한다.<br>
   * Given 영역은 테스트에 따라 필요하면 생성을 할 수 있고<br>
   * 기본적으로는 각 Entity 에 페이징이 가능한 수의 데이터를 설정해서<br>
   * Given 영역이 대부분의 Test 코드에서 필요없게 되었다.
   * @author FreshR
   * @since 2023. 1. 13. 오전 11:26:09
   */
  @Override
  public void run(ApplicationArguments args) {
    log.debug(" _______       ___   .___________.    ___         .______       _______     _______. _______ .___________.");
    log.debug("|       \\     /   \\  |           |   /   \\        |   _  \\     |   ____|   /       ||   ____||           |");
    log.debug("|  .--.  |   /  ^  \\ `---|  |----`  /  ^  \\       |  |_)  |    |  |__     |   (----`|  |__   `---|  |----`");
    log.debug("|  |  |  |  /  /_\\  \\    |  |      /  /_\\  \\      |      /     |   __|     \\   \\    |   __|      |  |     ");
    log.debug("|  '--'  | /  _____  \\   |  |     /  _____  \\     |  |\\  \\----.|  |____.----)   |   |  |____     |  |     ");
    log.debug("|_______/ /__/     \\__\\  |__|    /__/     \\__\\    | _| `._____||_______|_______/    |_______|    |__|     ");

    setAuth();
    setCommon();
    setCommunity();
  }

  /**
   * 권한 설정.
   *
   * @apiNote 권한 설정
   * @author FreshR
   * @since 2023. 1. 13. 오전 11:33:50
   */
  private void setAuth() {
    managerMajorId = service
        .createManager(MANAGER_MAJOR, MANAGER_MAJOR.name().toLowerCase(), MANAGER_MAJOR.name());
    managerMinorId = service
        .createManager(MANAGER_MINOR, MANAGER_MINOR.name().toLowerCase(), MANAGER_MINOR.name());
    staffMajorId = service
        .createStaff(STAFF_MAJOR, STAFF_MAJOR.name().toLowerCase(), STAFF_MAJOR.name());
    staffMinorId = service
        .createStaff(STAFF_MINOR, STAFF_MINOR.name().toLowerCase(), STAFF_MINOR.name());
    userId = service
        .createAccount(USER.name().toLowerCase(), USER.name());

    TokenProvider.signedId.set(managerMajorId);
  }

  /**
   * 공통 설정.
   *
   * @apiNote 공통 설정
   * @author FreshR
   * @since 2023. 1. 13. 오전 11:34:15
   */
  private void setCommon() {
    String dummy = "iVBORw0KGgoAAAANSUhEUgAAAGQAAABkBAMAAACCzIhnAAAAG1BMVEX///8AAAB/f38/Pz9fX18fHx+/v7/f39+fn585bAfnAAAACXBIWXMAAA7EAAAOxAGVKw4bAAABD0lEQVRYhe2UO0/DMBCAjxASRpwHMAYqpK5JEDNR+wNIyqNjJKR2TSmiaweG/uzasVPSQtS7Dh3QfUN8ufjz+RTLAAzDMAzDaBYdeSttiAB6JlQfPnMRJiX8JNPEKLZoeATIXjRqKfF8O8hD6WTNhKBdSpgxKzepm7F8OHeRfju52N3db8UVVT1WeOV8axcoxbomKzZdsTyy4vhkBeIlWZltNYNSnPwBp+jz8qriuSgqjDKqz59e/10EJUIp29mPPGjqYBXZzxtVATskKxBHZGX2RFbOrsjK6eUxlAM2Rmnf1f89i/CK4ynHDvffMPfDGlkl9vuTb4E4MOZeVGVUXECn8idfqylqHsMwDMP8Z9YwyTX+cM1Q2gAAAABJRU5ErkJggg==";
    byte[] bytes = Base64.getDecoder().decode(dummy);
    ByteArrayInputStream inputStream = new ByteArrayInputStream(bytes);

    try {
      minioService.put(IMAGE_PNG_VALUE, ".temp/dummy.png", inputStream);
    } catch (IOException | ServerException | InsufficientDataException | ErrorResponseException |
             NoSuchAlgorithmException | InvalidKeyException | InvalidResponseException |
             XmlParserException | InternalException e) {
      e.printStackTrace();
    }

    for (int i = 0; i < 45; i++) {
      attachIdList.add(service
          .createAttach("dummy.png", ".temp"));
    }
  }

  private void setCommunity() {
    Manager creator = service.getManager(managerMajorId);

    for (int i = 0; i < 15; i++) {
      String padding = StringUtil.padding(i + 1, 3);
      long id = service.createBoardNotice("title " + padding,
          "contents " + padding, false, BoardNoticeExpose.ALL, creator);

      for (int j = 0; j < 3; j++) {
        service.createBoardNoticeAttachMapping(id, attachIdList.get((i * 3) + j), i);
      }

      noticeIdList.add(id);
    }
  }

}
