package run.freshr.common.security;

import static com.google.common.base.CaseFormat.LOWER_HYPHEN;
import static com.google.common.base.CaseFormat.UPPER_UNDERSCORE;
import static io.jsonwebtoken.SignatureAlgorithm.HS512;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.isNull;
import static org.springframework.security.core.authority.AuthorityUtils.createAuthorityList;
import static org.springframework.util.StringUtils.hasLength;
import static run.freshr.domain.auth.enumeration.Role.ROLE_ANONYMOUS;
import static run.freshr.enumeration.StatusEnum.EXPIRED_JWT;
import static run.freshr.utils.CryptoUtil.encodeBase64;
import static run.freshr.utils.CryptoUtil.encryptSha256;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.HttpServletRequest;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import javax.crypto.spec.SecretKeySpec;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import run.freshr.common.data.ResponseData;
import run.freshr.domain.auth.enumeration.Role;
import run.freshr.domain.auth.redis.AccessRedis;
import run.freshr.domain.auth.unit.AccessRedisUnit;
import run.freshr.domain.auth.unit.RefreshRedisUnit;

/**
 * Token 관리 기능 정의.
 *
 * @author FreshR
 * @apiNote Token 관리 기능 정의
 * @since 2023. 1. 12. 오후 7:05:15
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class TokenProvider {

  private final AccessRedisUnit accessRedisUnit;
  private final RefreshRedisUnit refreshRedisUnit;

  private final ObjectMapper objectMapper;

  public static final String JWT_VARIABLE = "FRESHR"; // JWT 암호화 키 값 TODO: 설정 파일에서 관리할 수 있도록 수정 예정
  public static final String JWT_SHA = encryptSha256(JWT_VARIABLE);
  public static final byte[] JWT_BYTE = encodeBase64(JWT_SHA).getBytes(UTF_8); // JWT 암호화 키 Byte
  public static final Key JWT_KEY = new SecretKeySpec(JWT_BYTE, HS512.getJcaName()); // Key 생성
  public static final Integer EXPIRATION_ACCESS = 1000 * 60 * 15; // Access Token 만료 시간 TODO: 설정 파일에서 관리할 수 있도록 수정 예정
  public static final String AUTHORIZATION_STRING = "Authorization";
  public static final String BEARER_PREFIX = "Bearer ";
  public static ThreadLocal<Long> signedId = new ThreadLocal<>(); // 요청한 토큰의 계정 일련 번호
  public static ThreadLocal<Role> signedRole = new ThreadLocal<>(); // 요청한 토큰의 계정 권한

  /**
   * Access Token 생성.
   *
   * @param id id
   * @return string
   * @apiNote Access Token 생성
   * @author FreshR
   * @since 2023. 1. 12. 오후 7:05:15
   */
  public String generateAccessToken(final Long id) {
    return generate(id.toString(), EXPIRATION_ACCESS, null);
  }

  /**
   * Refresh Token 생성.
   *
   * @param id id
   * @return string
   * @apiNote Refresh Token 생성
   * @author FreshR
   * @since 2023. 1. 12. 오후 7:05:15
   */
  public String generateRefreshToken(final Long id) {
    return generate(id.toString(), null, null);
  }

  /**
   * JWT Token 생성.
   *
   * @param subject    subject
   * @param expiration expiration
   * @param claim      claim
   * @return string
   * @apiNote JWT Token 생성
   * @author FreshR
   * @since 2023. 1. 12. 오후 7:05:15
   */
  public String generate(final String subject, final Integer expiration,
      final HashMap<String, Object> claim) {
    JwtBuilder jwtBuilder = Jwts.builder()
        .setHeaderParam("typ", "JWT")
        .setSubject(subject)
        .setIssuedAt(new Date())
        .signWith(JWT_KEY);

    if (!isNull(claim)) { // 토큰 Body 설정
      jwtBuilder.setClaims(claim);
    }

    if (!isNull(expiration)) { // 만료 시간 설정
      jwtBuilder.setExpiration(new Date(new Date().getTime() + expiration));
    }

    return jwtBuilder.compact();
  }

  /**
   * 요청 정보에서 토큰 조회.
   *
   * @param request request
   * @return string
   * @apiNote 요청 정보에서 토큰 조회
   * @author FreshR
   * @since 2023. 1. 12. 오후 7:05:15
   */
  public String resolve(HttpServletRequest request) {
    String header = request.getHeader(AUTHORIZATION_STRING);

    return hasLength(header) ? header.replace(BEARER_PREFIX, "") : null;
  }

  /**
   * 토큰 정보를 조회.
   *
   * @param jwt jwt
   * @return claims
   * @throws JwtException jwt exception
   * @apiNote 토큰 정보를 조회
   * @author FreshR
   * @since 2023. 1. 12. 오후 7:05:15
   */
  public Claims get(final String jwt) throws JwtException {
    return Jwts
        .parserBuilder()
        .setSigningKey(JWT_KEY)
        .build()
        .parseClaimsJws(jwt)
        .getBody();
  }

  /**
   * Access 토큰 검증.
   *
   * @param token token
   * @return boolean
   * @apiNote Access 토큰 검증
   * @author FreshR
   * @since 2023. 1. 12. 오후 7:05:15
   */
  public boolean validateAccess(final String token) {
    if (!hasLength(token)) {
      return true;
    }

    if (!accessRedisUnit.exists(token)) { // 발급한 토큰인지 체크
      throw new ExpiredJwtException(null, null, "error validate token");
    }

    if (checkExpiration(token)) { // 만료되었는지 체크
      throw new ExpiredJwtException(null, null, "error validate token");
    }

    return true;
  }

  /**
   * Refresh 토큰 검증
   *
   * @param token token
   * @return boolean
   * @apiNote Refresh 토큰 검증
   * @author FreshR
   * @since 2023. 1. 12. 오후 7:05:16
   */
  public boolean validateRefresh(final String token) {
    if (!hasLength(token)) {
      return true;
    }

    if (!refreshRedisUnit.exists(token)) { // 발급한 토큰인지 체크
      throw new ExpiredJwtException(null, null, "error validate token");
    }

    if (checkExpiration(token)) { // 만료되었는지 체크
      throw new ExpiredJwtException(null, null, "error validate token");
    }

    return true;
  }

  /**
   * 토큰의 만료 여부 체크.
   *
   * @param jwt jwt
   * @return boolean
   * @throws JwtException jwt exception
   * @apiNote 토큰의 만료 여부 체크
   * @author FreshR
   * @since 2023. 1. 12. 오후 7:05:16
   */
  public boolean checkExpiration(final String jwt) throws JwtException {
    boolean flag = false;

    try {
      get(jwt);
    } catch (ExpiredJwtException e) {
      flag = true;
    }

    return flag;
  }

  /**
   * 토큰 정보 저장.
   *
   * @param accessToken access token
   * @apiNote 통신이 유지되는 동안 프로젝트 전역에서 접근할 수 있도록 토큰 정보를 저장
   * @author FreshR
   * @since 2023. 1. 12. 오후 7:05:16
   */
  public void setThreadLocal(String accessToken) {
    Long id = 0L;
    Role role = ROLE_ANONYMOUS;

    if (hasLength(accessToken)) {
      AccessRedis access = accessRedisUnit.get(accessToken);

      id = access.getSignId();
      role = access.getRole();
    }

    signedId.set(id);
    signedRole.set(role);
  }

  /**
   * 인증 정보 생성.
   *
   * @return authentication
   * @apiNote 인증 정보 생성
   * @author FreshR
   * @since 2023. 1. 12. 오후 7:05:16
   */
  public Authentication getAuthentication() {
    Role role = signedRole.get();

    return new UsernamePasswordAuthenticationToken(
        role.getPrivilege(),
        "{noop}",
        createAuthorityList(role.getKey())
    );
  }

  /**
   * 만료되었을 때 반환 데이터 설정.
   *
   * @return string
   * @throws JsonProcessingException json processing exception
   * @apiNote 만료되었을 때 반환 데이터 설정
   * @author FreshR
   * @since 2023. 1. 12. 오후 7:05:16
   */
  public String expiredJwt() throws JsonProcessingException {
    return objectMapper.writeValueAsString(ResponseData
        .builder()
        .name(UPPER_UNDERSCORE.to(LOWER_HYPHEN, EXPIRED_JWT.name()))
        .message(EXPIRED_JWT.getMessage())
        .build());
  }

}
