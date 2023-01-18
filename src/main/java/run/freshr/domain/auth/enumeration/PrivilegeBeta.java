package run.freshr.domain.auth.enumeration;

import lombok.extern.slf4j.Slf4j;
import run.freshr.mappers.EnumModel;

import static java.util.Arrays.stream;
import static run.freshr.domain.auth.enumeration.Role.ROLE_BETA;
import static run.freshr.domain.auth.enumeration.Role.ROLE_DELTA;

/**
 * Privilege.
 *
 * @author FreshR
 * @apiNote 권한 목록
 * @since 2022. 12. 23. 오후 4:23:59
 */
@Slf4j
public enum PrivilegeBeta implements EnumModel {

  BETA("최상위 관리자", ROLE_BETA),
  GAMMA("상위 관리자", ROLE_DELTA),
  DELTA("관리자", ROLE_DELTA);

  private final String value;
  private final Role role;

  /**
   * Instantiates a new Privilege.
   *
   * @param value value
   * @apiNote api note
   * @author FreshR
   * @since 2022. 12. 23. 오후 4:23:59
   */
  PrivilegeBeta(String value, Role role) {
    this.value = value;
    this.role = role;
  }

  public static PrivilegeBeta find(String key) {
    log.info("Privilege.find");

    return stream(PrivilegeBeta.values())
        .filter(item -> item.getKey().equalsIgnoreCase(key))
        .findAny()
        .orElse(null);
  }

  @Override
  public String getKey() {
    return name();
  }

  @Override
  public String getValue() {
    return this.value;
  }

}
