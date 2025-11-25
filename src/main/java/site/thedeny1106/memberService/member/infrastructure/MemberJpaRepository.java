package site.thedeny1106.memberService.member.infrastructure;

import org.springframework.data.jpa.repository.JpaRepository;
import site.thedeny1106.memberService.member.domain.Member;

import java.util.Optional;
import java.util.UUID;

public interface MemberJpaRepository extends JpaRepository<Member, UUID> {

    Optional<Member> findByEmail(String email);
}
