package site.thedeny1106.memberService.member.applicaation.dto;

public record MemberCommand(
        String email,
        String name,
        String password,
        String phone
) {
}
