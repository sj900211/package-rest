package run.freshr.controller;

import static org.springframework.restdocs.payload.PayloadDocumentation.requestFields;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static run.freshr.TestRunner.userId;
import static run.freshr.common.config.URIConfig.uriAuthCrypto;
import static run.freshr.common.config.URIConfig.uriAuthInfo;
import static run.freshr.common.config.URIConfig.uriAuthPassword;
import static run.freshr.common.config.URIConfig.uriAuthSignIn;
import static run.freshr.common.config.URIConfig.uriAuthSignOut;
import static run.freshr.common.config.URIConfig.uriAuthToken;
import static run.freshr.common.util.ThreadUtil.threadPublicKey;
import static run.freshr.common.util.ThreadUtil.threadRefresh;
import static run.freshr.utils.CryptoUtil.encryptRsa;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import run.freshr.annotation.Docs;
import run.freshr.annotation.DocsGroup;
import run.freshr.annotation.DocsPopup;
import run.freshr.common.extension.TestExtension;
import run.freshr.domain.auth.AccountDocs;
import run.freshr.domain.auth.CryptoDocs;
import run.freshr.domain.auth.ManagerDocs;
import run.freshr.domain.auth.SignDocs;
import run.freshr.domain.auth.StaffDocs;
import run.freshr.domain.auth.dto.request.EncryptRequest;
import run.freshr.domain.auth.dto.request.RefreshTokenRequest;
import run.freshr.domain.auth.dto.request.SignChangePasswordRequest;
import run.freshr.domain.auth.dto.request.SignInRequest;
import run.freshr.domain.auth.dto.request.SignUpdateRequest;

@Slf4j
@DisplayName("권한 관리")
@DocsGroup(name = "auth")
public class AuthControllerTest extends TestExtension {

  @Test
  @DisplayName("RSA 공개키 조회")
  @Docs(existsResponseFields = true)
  public void getPublicKey() throws Exception {
    log.info("AuthControllerTest.getPublicKey");

    setAnonymous();

    GET(uriAuthCrypto)
        .andDo(print())
        .andDo(docs(responseFields(CryptoDocs.Response.getPublicKey())))
        .andExpect(status().isOk());
  }

  @Test
  @DisplayName("RSA 암호화 - 사용하지 않을 것을 권장")
  @Docs(existsRequestFields = true, existsResponseFields = true)
  public void getEncryptRsa() throws Exception {
    log.info("AuthControllerTest.getPublicKey");

    setAnonymous();
    setRsa();

    POST_BODY(uriAuthCrypto,
        EncryptRequest
            .builder()
            .rsa(threadPublicKey.get())
            .plain("plain text")
            .build())
        .andDo(print())
        .andDo(docs(requestFields(CryptoDocs.Request.getEncryptRsa()),
            responseFields(CryptoDocs.Response.getEncryptRsa())))
        .andExpect(status().isOk());
  }

  @Test
  @DisplayName("로그인")
  @Docs(existsRequestFields = true, existsResponseFields = true)
  public void signIn() throws Exception {
    log.info("AuthControllerTest.signIn");

    setAnonymous();
    setRsa();

    apply();

    POST_BODY(
        uriAuthSignIn,
        SignInRequest
            .builder()
            .rsa(threadPublicKey.get())
            .username(encryptRsa(
                service.getAccount(userId).getUsername(),
                threadPublicKey.get()))
            .password(encryptRsa("1234", threadPublicKey.get()))
            .build()
    ).andDo(print())
        .andDo(docs(
            requestFields(SignDocs.Request.signIn()),
            responseFields(SignDocs.Response.signIn())
        ))
        .andExpect(status().isOk());
  }

  @Test
  @DisplayName("로그아웃")
  @Docs
  public void signOut() throws Exception {
    log.info("AuthControllerTest.signOut");

    setSignedUser();

    apply();

    POST(uriAuthSignOut)
        .andDo(print())
        .andExpect(status().isOk());
  }

  @Test
  @DisplayName("로그인 계정 정보 조회 - MANAGER")
  @Docs(existsResponseFields = true)
  public void getInfoForManager() throws Exception {
    log.info("AuthControllerTest.getInfoForManager");

    setSignedManagerMinor();

    apply();

    GET(uriAuthInfo)
        .andDo(print())
        .andDo(docs(responseFields(ManagerDocs.Response.getInfo())))
        .andExpect(status().isOk());
  }

  @Test
  @DisplayName("로그인 계정 정보 조회 - STAFF")
  @Docs(existsResponseFields = true)
  public void getInfoForStaff() throws Exception {
    log.info("AuthControllerTest.getInfoForStaff");

    setSignedStaffMinor();

    apply();

    GET(uriAuthInfo)
        .andDo(print())
        .andDo(docs(responseFields(StaffDocs.Response.getInfo())))
        .andExpect(status().isOk());
  }

  @Test
  @DisplayName("로그인 계정 정보 조회 - USER")
  @Docs(existsResponseFields = true)
  public void getInfoForUser() throws Exception {
    log.info("AuthControllerTest.getInfoForUser");

    setSignedUser();

    apply();

    GET(uriAuthInfo)
        .andDo(print())
        .andDo(docs(responseFields(AccountDocs.Response.getInfo())))
        .andExpect(status().isOk());
  }

  @Test
  @DisplayName("로그인 계정 비밀번호 변경")
  @Docs(existsRequestFields = true)
  public void updatePassword() throws Exception {
    log.info("AuthControllerTest.updatePassword");

    setSignedUser();
    setRsa();

    apply();

    PUT_BODY(
        uriAuthPassword,
        SignChangePasswordRequest
            .builder()
            .rsa(threadPublicKey.get())
            .originPassword(encryptRsa("1234", threadPublicKey.get()))
            .password(encryptRsa("input password", threadPublicKey.get()))
            .build()
    ).andDo(print())
        .andDo(docs(requestFields(SignDocs.Request.updatePassword())))
        .andExpect(status().isOk());
  }

  @Test
  @DisplayName("로그인 계정 정보 수정 - MANAGER")
  @Docs(existsRequestFields = true, popup = {
      @DocsPopup(name = "manager-docs-get-info-privilege",
          include = "common-controller-test/get-enum-list/popup/popup-fields-privilege.adoc")
  })
  public void updateInfoForManager() throws Exception {
    log.info("AuthControllerTest.updateInfoForManager");

    setSignedManagerMinor();
    setRsa();

    apply();

    PUT_BODY(
        uriAuthInfo,
        SignUpdateRequest
            .builder()
            .rsa(threadPublicKey.get())
            .name(encryptRsa("input name", threadPublicKey.get()))
            .build()
    ).andDo(print())
        .andDo(docs(requestFields(ManagerDocs.Request.updateInfo())))
        .andExpect(status().isOk());
  }

  @Test
  @DisplayName("로그인 계정 정보 수정 - STAFF")
  @Docs(existsRequestFields = true, popup = {
      @DocsPopup(name = "staff-docs-get-info-privilege",
          include = "common-controller-test/get-enum-list/popup/popup-fields-privilege.adoc")
  })
  public void updateInfoForStaff() throws Exception {
    log.info("AuthControllerTest.updateInfoForStaff");

    setSignedStaffMinor();
    setRsa();

    apply();

    PUT_BODY(
        uriAuthInfo,
        SignUpdateRequest
            .builder()
            .rsa(threadPublicKey.get())
            .name(encryptRsa("input name", threadPublicKey.get()))
            .build()
    ).andDo(print())
        .andDo(docs(requestFields(StaffDocs.Request.updateInfo())))
        .andExpect(status().isOk());
  }

  @Test
  @DisplayName("로그인한 계정 정보 수정 - USER")
  @Docs(existsRequestFields = true, popup = {
      @DocsPopup(name = "user-docs-get-info-privilege",
          include = "common-controller-test/get-enum-list/popup/popup-fields-privilege.adoc")
  })
  public void updateInfoForUser() throws Exception {
    log.info("AuthControllerTest.updateInfoForUser");

    setSignedUser();
    setRsa();

    apply();

    PUT_BODY(
        uriAuthInfo,
        SignUpdateRequest
            .builder()
            .rsa(threadPublicKey.get())
            .name(encryptRsa("input name", threadPublicKey.get()))
            .build()
    ).andDo(print())
        .andDo(docs(requestFields(AccountDocs.Request.updateInfo())))
        .andExpect(status().isOk());
  }

  @Test
  @DisplayName("로그인한 계정 탈퇴 처리 - MANAGER")
  @Docs
  public void removeInfoForManager() throws Exception {
    log.info("AuthControllerTest.removeInfoForManager");

    setSignedManagerMinor();

    apply();

    DELETE(uriAuthInfo)
        .andDo(print())
        .andExpect(status().isOk());
  }

  @Test
  @DisplayName("로그인한 계정 탈퇴 처리 - STAFF")
  @Docs
  public void removeInfoForStaff() throws Exception {
    log.info("AuthControllerTest.removeInfoForStaff");

    setSignedStaffMinor();

    apply();

    DELETE(uriAuthInfo)
        .andDo(print())
        .andExpect(status().isOk());
  }

  @Test
  @DisplayName("로그인한 계정 탈퇴 처리 - USER")
  @Docs
  public void removeInfoForUser() throws Exception {
    log.info("AuthControllerTest.removeInfoForUser");

    setSignedUser();

    apply();

    DELETE(uriAuthInfo)
        .andDo(print())
        .andExpect(status().isOk());
  }

  @Test
  @DisplayName("Access 토큰 갱신")
  @Docs(existsRequestFields = true, existsResponseFields = true)
  public void refreshToken() throws Exception {
    log.info("AuthControllerTest.refreshToken");

    setSignedManagerMajor();

    apply();

    POST_BODY(uriAuthToken,
        RefreshTokenRequest
            .builder()
            .refreshToken(threadRefresh.get())
            .build())
        .andDo(print())
        .andDo(docs(
            requestFields(SignDocs.Request.refreshToken()),
            responseFields(SignDocs.Response.refreshToken())
        ))
        .andExpect(status().isOk());
  }

}
