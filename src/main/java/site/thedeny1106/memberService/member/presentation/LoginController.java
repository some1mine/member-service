package site.thedeny1106.memberService.member.presentation;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;
import site.thedeny1106.memberService.common.ResponseEntity;
import site.thedeny1106.memberService.member.applicaation.MemberService;
import site.thedeny1106.memberService.member.presentation.dto.LoginRequest;

import java.util.Map;

@RestController
@RequiredArgsConstructor
public class LoginController {
    private final MemberService memberService;

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody LoginRequest request) {
        return memberService.login(request);
    }

    @GetMapping("/api/v1/authorizations/check")
    public Boolean check(@RequestParam("httpMethod") String httpMethod, @RequestParam("requestPath") String requestPath){
        return memberService.check(httpMethod, requestPath);
    }

    @GetMapping("${api.v1}/refresh/token")
    public ResponseEntity<Map<String, Object>> refreshToken(@RequestHeader("refresh-token") String token){
        return memberService.refreshToken(token);
    }
}
