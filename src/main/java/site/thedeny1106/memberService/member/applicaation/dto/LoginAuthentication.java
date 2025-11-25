package site.thedeny1106.memberService.member.applicaation.dto;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class LoginAuthentication extends UsernamePasswordAuthenticationToken {
    public LoginAuthentication(Object principal, Object credentials) {
        super(principal, credentials);
    }
    public LoginAuthentication(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(principal, credentials, authorities);
    }
}
