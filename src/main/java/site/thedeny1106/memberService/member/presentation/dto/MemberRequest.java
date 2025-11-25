package site.thedeny1106.memberService.member.presentation.dto;

import site.thedeny1106.memberService.member.applicaation.dto.MemberCommand;

public record MemberRequest(
        String email,
        String name,
        String password,
        String phone
) {
    public MemberCommand toCommand() {
        return new MemberCommand(
                this.email,
                this.name,
                this.password,
                this.phone
        );
    }
}
