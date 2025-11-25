package site.thedeny1106.memberService.member.presentation;

import io.swagger.v3.oas.annotations.Operation;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Pageable;
import org.springframework.web.bind.annotation.*;
import site.thedeny1106.memberService.common.ResponseEntity;
import site.thedeny1106.memberService.member.applicaation.MemberService;
import site.thedeny1106.memberService.member.applicaation.dto.MemberInfo;
import site.thedeny1106.memberService.member.presentation.dto.MemberRequest;

import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("${api.v1}/members")
public class MemberController {

    private final MemberService memberService;

    @Operation(
            summary = "전체 회원 조회",
            description = "전체 회원 목록을 조회한다."
    )
    @GetMapping
    public ResponseEntity<List<MemberInfo>> findAll(Pageable pageable) {
        return memberService.findAll(pageable);
    }

    @Operation(
            summary = "회원 등록",
            description = "요청으로 받은 회원 정보를 public.member에 저장한다."
    )
    @PostMapping
    public ResponseEntity<MemberInfo> create(@RequestBody MemberRequest request) {
        return memberService.create(request.toCommand());
    }



    @Operation(
            summary = "회원 정보 수정",
            description = "수정할 정보를 받아 public.member의 레코드를 수정한다."
    )
    @PutMapping("/{id}")
    public ResponseEntity<MemberInfo> update(@RequestBody MemberRequest request, @PathVariable String id) {
        return memberService.update(id, request.toCommand());
    }

    @Operation(
            summary = "회원 정보 삭제",
            description = "id로 회원 삭제"
    )
    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(@PathVariable String id) {
        return memberService.delete(id);
    }
}
