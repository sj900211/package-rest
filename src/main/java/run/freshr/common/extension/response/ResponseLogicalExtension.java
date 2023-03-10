package run.freshr.common.extension.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * 논리 삭제 정책을 가진 데이터의 공통 필드를 정의한 Response.
 *
 * @param <ID> ID 데이터 유형
 * @author FreshR
 * @apiNote 논리 삭제 정책을 가진 데이터의 공통 필드를 정의한 Response
 * @since 2023. 1. 12. 오후 6:27:45
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ResponseLogicalExtension<ID> {

  protected ID id;

  protected LocalDateTime createAt;

  protected LocalDateTime updateAt;

}
