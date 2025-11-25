package site.thedeny1106.memberService.common;

public record ResponseEntity<T>(int status, T data, long count) {
}
