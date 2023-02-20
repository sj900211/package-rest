package run.freshr.common.security;

import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;
import static run.freshr.common.security.TokenProvider.signedId;
import static run.freshr.common.security.TokenProvider.signedRole;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * 권한 Filter.
 *
 * @author FreshR
 * @apiNote 권한 Filter
 * @since 2023. 1. 12. 오후 6:54:32
 */
@Slf4j
@RequiredArgsConstructor
public class TokenAuthenticationFilter extends OncePerRequestFilter {

  private TokenProvider provider;

  public TokenAuthenticationFilter(TokenProvider provider) {
    this.provider = provider;
  }

  /**
   * filter 프로세스.
   *
   * @param request     request
   * @param response    response
   * @param filterChain filter chain
   * @apiNote {@link TokenProvider} 를 사용해서<br>
   * 요청 정보에서 토큰을 조회, 검증하는 단계를 거쳐<br>
   * 인증 처리
   * @author FreshR
   * @since 2023. 1. 12. 오후 6:54:32
   */
  @Override
  protected void doFilterInternal(@NotNull HttpServletRequest request,
      @NotNull HttpServletResponse response, @NotNull FilterChain filterChain) {
    log.debug("**** SECURITY FILTER START");

    try {
      String accessToken = provider.resolve(request);

      provider.validateAccess(accessToken);
      provider.setThreadLocal(accessToken);

      SecurityContextHolder.getContext().setAuthentication(provider.getAuthentication());

      log.debug("**** Role: " + signedRole.get().name());
      log.debug("**** Id: " + signedId.get());

      filterChain.doFilter(request, response);
    } catch (ExpiredJwtException e) {
      log.error("**** ExpiredJwtException ****");
      log.error("**** error message : " + e.getMessage());
      log.error("**** stack trace : " + Arrays.toString(e.getStackTrace()));

      SecurityContextHolder.clearContext();

      try {
        response.setStatus(INTERNAL_SERVER_ERROR.value());
        response.getWriter().write(provider.expiredJwt());
      } catch (IOException ex) {
        log.error("**** ExpiredJwtException > IOException ****");
        log.error("**** error message : " + e.getMessage());
        log.error("**** stack trace : " + Arrays.toString(e.getStackTrace()));

        ex.printStackTrace();
      }

      e.printStackTrace();
    } catch (Exception e) {
      log.error("**** Exception ****");
      log.error("**** error message : " + e.getMessage());
      log.error("**** stack trace : " + Arrays.toString(e.getStackTrace()));

      SecurityContextHolder.clearContext();

      response.setStatus(INTERNAL_SERVER_ERROR.value());

      e.printStackTrace();
    } finally {
      log.debug("**** SECURITY FILTER FINISH");
    }
  }

}
