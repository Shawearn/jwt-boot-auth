package com.example.jwtauth;

import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

/**
 * 实现 token 的校验功能；
 */
public class JwtAuthenticationFilter extends BasicAuthenticationFilter {

    public JwtAuthenticationFilter(AuthenticationManager authManager) {
        super(authManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req,
                                    HttpServletResponse res,
                                    FilterChain chain) throws IOException, ServletException {
        // 从 http 头的 Authorization 项读取 token 数据；
        String header = req.getHeader("Authorization");

        if (header == null || !header.startsWith("Bearer ")) {
            chain.doFilter(req, res);
            return;
        }

        // 如果校验通过，就认为这是一个取得授权的合法请求
        UsernamePasswordAuthenticationToken authentication = getAuthentication(req);

        SecurityContextHolder.getContext().setAuthentication(authentication);
        chain.doFilter(req, res);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
        String token = request.getHeader("Authorization");
        if (token == null || "".equals(token)) {
            return null;
        }
        // 用 Jwts 包提供的方法校验 token 的合法性；
        String user = Jwts.parser()
                .setSigningKey("MyJwtSecret")
                .parseClaimsJws(token.replace("Bearer ", ""))
                .getBody()
                .getSubject();
        if (user == null) {
            return null;
        }
        // 如果校验通过，就认为这是一个取得授权的合法请求；
        return new UsernamePasswordAuthenticationToken(user, null, new ArrayList<>());
    }
}