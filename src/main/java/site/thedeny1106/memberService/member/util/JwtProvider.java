package site.thedeny1106.memberService.member.util;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

@Component
public class JwtProvider {
    @Value("${token.seed.secret}")
    String TOKEN_SECRET;

    private static final long JWT_EXPIRATION_MS = 86400000L * 7;

    public String generateToken(Authentication authentication) {
        Date now = new Date();
        Date expireDate = new Date(now.getTime() + JWT_EXPIRATION_MS);
        String secretKey = Base64.getEncoder().encodeToString(TOKEN_SECRET.getBytes());

        return Jwts.builder().subject(authentication.getPrincipal().toString())
                .issuedAt(now)
                .expiration(expireDate)
                .signWith(Keys.hmacShaKeyFor(Base64.getDecoder().decode(secretKey)), Jwts.SIG.HS512)
                .compact();
    }

    public boolean validateToken(String token) {
        String secretKey = Base64.getEncoder().encodeToString(TOKEN_SECRET.getBytes());
        try {
            Jwts.parser().verifyWith(Keys.hmacShaKeyFor(Base64.getDecoder().decode(secretKey))).build()
                    .parseSignedClaims(token);
            return true;
        } catch (ExpiredJwtException exception) {
            throw new JwtException("expired");
        } catch (JwtException exception) {
            throw new JwtException("jwt error");
        } catch (Exception exception) {
            throw new RuntimeException(Arrays.toString(exception.getStackTrace()));
        }
    }

    public String getUserDataFromJWT(String token) {
        try {
            return Jwts.parser().verifyWith(Keys.hmacShaKeyFor(TOKEN_SECRET.getBytes())).build()
                    .parseSignedClaims(token).getPayload().getSubject();
        } catch (ExpiredJwtException exception) {
            throw new JwtException("expired");
        } catch (JwtException exception) {
            throw new JwtException("jwt error");
        } catch (Exception exception) {
            throw new RuntimeException(Arrays.toString(exception.getStackTrace()));
        }
    }
}
