package io.security.corespringsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

//    @Autowired
//    UserDetailsService userDetailsService;

//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER"); // 메모리 방식으로 사용자 생성
//        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS","USER");
//        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN","SYS","USER");
//    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
//                .antMatchers("/login").permitAll()
//                .antMatchers("/user").hasRole("USER")
//                .antMatchers("/admin/pay").hasRole("ADMIN")
//                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated();
        http
                .formLogin();
//                .successHandler(new AuthenticationSuccessHandler() {
//                    // 인증에 실패했다가 성공하면 실패했을때 세션캐시에 저장하기 때문에
//                    // 로그인성공시 바로 캐시에 저장했던 url를 보내주는 코드
//                    @Override
//                    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
//                        RequestCache requestCache = new HttpSessionRequestCache();
//                        SavedRequest savedRequest = requestCache.getRequest(httpServletRequest, httpServletResponse);
//                        String redirectUrl = savedRequest.getRedirectUrl();
//                        httpServletResponse.sendRedirect(redirectUrl);
//                    }
//                });

//        http
//                .exceptionHandling()
//                .authenticationEntryPoint(new AuthenticationEntryPoint() {
//                    @Override
//                    public void commence(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
//                        httpServletResponse.sendRedirect("/login");
//                    }
//                })
//                .accessDeniedHandler(new AccessDeniedHandler() {
//                    @Override
//                    public void handle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AccessDeniedException e) throws IOException, ServletException {
//                        httpServletResponse.sendRedirect("/denied");
//                    }
//                });
//        .and()
//                .sessionManagement()
//                .maximumSessions(1)
//                .maxSessionsPreventsLogin(false);


//        http
//                .sessionManagement()
//                .sessionFixation().changeSessionId();

        // 1-9 동시 세션 제어
//        http
//                .sessionManagement()
//                .maximumSessions(1)
//                .maxSessionsPreventsLogin(false);
        // 1-3 form 로그인 방식 코드
//                .loginPage("/loginPage")
//                .defaultSuccessUrl("/")
//                .failureUrl("/login")
//                .usernameParameter("userId")
//                .passwordParameter("passwd")
//                .loginProcessingUrl("/login_proc")
//                .successHandler(new AuthenticationSuccessHandler() {
//                    @Override
//                    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
//                        System.out.println("authentication : " + authentication.getName());
//                        httpServletResponse.sendRedirect("/");
//                    }
//                })
//                .failureHandler(new AuthenticationFailureHandler() {
//                    @Override
//                    public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
//                        System.out.println("e = " + e.getMessage());
//                        httpServletResponse.sendRedirect("/login");
//                    }
//                })
//                .permitAll();

//        http
//                // 1-5 logout 처리
//                .logout()
//                .logoutUrl("/logout")
//                .logoutSuccessUrl("/login")
//                .addLogoutHandler(new LogoutHandler() {
//                    @Override
//                    public void logout(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) {
//                        HttpSession session = httpServletRequest.getSession();
//                        session.invalidate();
//                    }
//                })
//                .logoutSuccessHandler(new LogoutSuccessHandler() {
//                    @Override
//                    public void onLogoutSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
//                        httpServletResponse.sendRedirect("/login");
//                    }
//                })
        // 1-7 remember me 인증 필터
//                .and()
//                .rememberMe()
//                .rememberMeParameter("remember")
//                .tokenValiditySeconds(3600)
//                .userDetailsService(userDetailsService);

    }
}
