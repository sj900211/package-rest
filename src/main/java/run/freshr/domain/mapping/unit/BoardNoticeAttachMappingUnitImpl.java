package run.freshr.domain.mapping.unit;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.transaction.annotation.Transactional;
import run.freshr.annotations.Unit;
import run.freshr.domain.community.entity.BoardNotice;
import run.freshr.domain.mapping.embedded.BoardNoticeAttachMappingEmbeddedId;
import run.freshr.domain.mapping.entity.BoardNoticeAttachMapping;
import run.freshr.domain.mapping.repository.jpa.BoardNoticeAttachMappingRepository;

@Slf4j
@Unit
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class BoardNoticeAttachMappingUnitImpl implements BoardNoticeAttachMappingUnit {

  private final BoardNoticeAttachMappingRepository repository;

  @Override
  @Transactional
  public BoardNoticeAttachMappingEmbeddedId create(BoardNoticeAttachMapping entity) {
    log.info("BoardNoticeAttachMappingUnit.create");

    return repository.save(entity).getId();
  }

  @Override
  public Boolean exists(BoardNoticeAttachMappingEmbeddedId id) {
    log.info("BoardNoticeAttachMappingUnit.exists");

    return repository.existsById(id);
  }

  @Override
  @Transactional
  public BoardNoticeAttachMapping get(BoardNoticeAttachMappingEmbeddedId id) {
    log.info("BoardNoticeAttachMappingUnit.get");

    return repository.findById(id).orElseThrow(EntityNotFoundException::new);
  }

  @Override
  @Transactional
  public void delete(BoardNotice entity) {
    log.info("BoardNoticeAttachMappingUnit.delete");

    repository.deleteAllByNotice(entity);
  }

}
