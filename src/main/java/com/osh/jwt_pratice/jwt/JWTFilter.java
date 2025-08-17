package com.osh.jwt_pratice.jwt;

import com.osh.jwt_pratice.dto.CustomUserDetails;
import com.osh.jwt_pratice.entity.UserEntity;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@RequiredArgsConstructor
public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // Header에서 Authorization 가지고오기
        String authorization = request.getHeader("Authorization");

        // Header에 Authorization 유무 확인
        // 있으면 계속 진행 없으면 다음 필터로 진행
        if( authorization == null || !authorization.startsWith("Bearer ")) {
            System.out.println("token null : " + authorization);
            filterChain.doFilter(request, response);

            return;
        }

        System.out.println("authorization now");

        // Authorization에서 Bearer을 제외한 토큰 획득
        String token = authorization.split(" ")[1];

        // JWTUtils로 유효기간 검증
        // 유효기간이 만료되면 다음 필터로 이동
        if(jwtUtil.isExpired(token)) {
            System.out.println("token expired");

            filterChain.doFilter(request, response);
            return;
        }

        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);

        UserEntity userEntity = new UserEntity();
        userEntity.setUsername(username);
        userEntity.setPassword("tempPassword");
        userEntity.setRole(role);

        // userDetails에 회원 정보 객체 담기
        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);

        // 스프링 시큐리티 인증 토큰 생성
        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());

        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);

    }
}
