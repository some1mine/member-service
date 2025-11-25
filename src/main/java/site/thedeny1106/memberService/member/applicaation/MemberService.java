package site.thedeny1106.memberService.member.applicaation;

import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import site.thedeny1106.memberService.common.ResponseEntity;
import site.thedeny1106.memberService.member.applicaation.dto.LoginAuthentication;
import site.thedeny1106.memberService.member.applicaation.dto.MemberCommand;
import site.thedeny1106.memberService.member.applicaation.dto.MemberInfo;
import site.thedeny1106.memberService.member.domain.Member;
import site.thedeny1106.memberService.member.domain.MemberRepository;
import site.thedeny1106.memberService.member.presentation.dto.LoginRequest;
import site.thedeny1106.memberService.member.util.JwtProvider;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class MemberService {
    private final JwtProvider jwtProvider;
    private final PasswordEncoder passwordEncoder;
    private final MemberRepository memberRepository;

    public ResponseEntity<List<MemberInfo>> findAll(Pageable pageable) {
        Page<Member> page = memberRepository.findAll(pageable);
        List<MemberInfo> members = page.stream()
                .map(MemberInfo::from)
                .toList();
        return new ResponseEntity<>(HttpStatus.OK.value(), members, page.getTotalElements());
    }

    public ResponseEntity<MemberInfo> create(MemberCommand command) {

        Member member = Member.create(
                command.email(),
                command.name(),
                passwordEncoder.encode(command.password()),
                command.phone()
        );
        MemberInfo response = MemberInfo.from(memberRepository.save(member));

        return new ResponseEntity<>(HttpStatus.OK.value(), response, 1);
    }

    public ResponseEntity<MemberInfo> update(String id, MemberCommand command) {
        Member found = memberRepository.findById(UUID.fromString(id)).orElse(null);
        if (found == null) return new ResponseEntity<>(HttpStatus.NOT_FOUND.value(), null, 0);
        String password = command.password() == null || command.password().isBlank()
                ? found.getPassword()
                : passwordEncoder.encode(command.password());

        Member member = Member.update(
                command.email(),
                command.name(),
                password,
                command.phone(),
                "act"
        );

        MemberInfo response = MemberInfo.from(memberRepository.save(member));

        return new ResponseEntity<>(HttpStatus.OK.value(), response, 1);
    }

    public ResponseEntity<?> delete(String id) {
        memberRepository.deleteById(UUID.fromString(id));
        return new ResponseEntity<>(HttpStatus.OK.value(), 1, 1);
    }

    public ResponseEntity<Map<String, Object>> login(LoginRequest request) {
        Optional<Member> result = memberRepository.findByEmail(request.id());
        if (result.isEmpty()) return new ResponseEntity<>(HttpStatus.NOT_FOUND.value(),
                Map.of(HttpStatus.NOT_FOUND.toString(), "해당 이메일의 사용자가 존재하지 않습니다."), 0);
        Member member = result.get();
        if (passwordEncoder.matches(request.pw(), member.getPassword())) {
            Authentication authentication = new LoginAuthentication(member.getId().toString(), null);
            String token = jwtProvider.generateToken(authentication);
            Map<String, Object> data = Map.of("token", token);
            return new ResponseEntity<>(HttpStatus.OK.value(), data, 1);
        }
        return null;
    }

    public boolean check(String method, String path) {
        return true;
    }
}
