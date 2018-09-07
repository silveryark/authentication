package com.silveryark.authentication;

import com.silveryark.rpc.RPCHttpHeaders;
import com.silveryark.rpc.RPCResponse;
import com.silveryark.rpc.authentication.AuthorizeRequest;
import com.silveryark.rpc.authentication.AuthorizeResponse;
import com.silveryark.security.JwtSecurityService;
import com.silveryark.utils.Dates;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.http.codec.CodecConfigurer;
import org.springframework.http.codec.HttpMessageWriter;
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.web.reactive.function.BodyExtractors;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import org.springframework.web.reactive.result.view.ViewResolver;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Collections;
import java.util.Date;
import java.util.List;

@EnableWebFluxSecurity
public class SecurityConfig {

    private static final int EXPIRES_DAYS = 30;

    @Bean
    public SecurityWebFilterChain securitygWebFilterChain(ServerHttpSecurity http,
                                                          AuthenticationWebFilter authenticationWebFilter) {
        return http.exceptionHandling()
                .and()
                //鉴权处理
                .addFilterAt(authenticationWebFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                //所有接口都需要授权（实际上这个服务里应该也没有别的接口才对）
                .authorizeExchange().anyExchange().authenticated()
                .and()
                //取消其它的登陆方式
                .formLogin().disable()
                .httpBasic().disable()
                .logout().disable()
                .csrf().disable()
                .build();
    }

    //把客户端传过来的username/password信息抽取出来
    @Bean
    public AuthenticationWebFilter authenticationWebFilter(
            UserDetailsRepositoryReactiveAuthenticationManager reactiveAuthenticationManager,
            CodecConfigurer configurer,
            ServerAuthenticationSuccessHandler successHandler,
            ServerAuthenticationFailureHandler failureHandler) {
        AuthenticationWebFilter authenticationWebFilter = new AuthenticationWebFilter(reactiveAuthenticationManager);
        authenticationWebFilter.setAuthenticationConverter((ServerWebExchange exchange) -> {
            //这里使用 ServerRequest，就可以直接使用BodyExtractor来处理信息，否则还要根据http header来判断数据格式，
            ServerRequest serverRequest = ServerRequest.create(exchange, configurer.getReaders());
            Mono<AuthorizeRequest> authorizeRequestMono =
                    serverRequest.body(BodyExtractors.toMono(AuthorizeRequest.class));
            return authorizeRequestMono.map((AuthorizeRequest request) -> {
                //直接转成AuthenticationToken
                AuthorizeRequest.Credential payload = request.getPayload();
                String username = payload.getUsername();
                String password = payload.getPassword();
                return new UsernamePasswordAuthenticationToken(username, password);
            });
        });
        //只check这个path，完成登陆
        authenticationWebFilter.setRequiresAuthenticationMatcher(new PathPatternParserServerWebExchangeMatcher(
                "/token", HttpMethod.POST));
        authenticationWebFilter.setAuthenticationSuccessHandler(successHandler);
        authenticationWebFilter.setAuthenticationFailureHandler(failureHandler);
        return authenticationWebFilter;
    }

    //失败的时候返回相应异常
    @Bean
    public ServerAuthenticationFailureHandler failureHandler(CodecConfigurer configurer) {
        return ((WebFilterExchange webFilterExchange, AuthenticationException exception) -> {
            ServerWebExchange exchange = webFilterExchange.getExchange();
            //取出来requestId，为了构建response
            String requestId = exchange.getRequest().getHeaders().get(RPCHttpHeaders.REQUEST_ID).get(0);
            return ServerResponse
                    .ok()
                    .body(BodyInserters.fromObject(new AuthorizeResponse(requestId, RPCResponse.STATUS.OK,
                            exception)))
                    //通过 configurer获取writer，来"智能"地完成消息转换
                    .flatMap((ServerResponse response) -> response.writeTo(exchange, new ServerResponse.Context() {
                        @Override
                        public List<HttpMessageWriter<?>> messageWriters() {
                            return configurer.getWriters();
                        }

                        @Override
                        public List<ViewResolver> viewResolvers() {
                            return Collections.emptyList();
                        }
                    }));
        });
    }

    //把成功认证的信息写到输出里（返回 jwtToken）
    @Bean
    public ServerAuthenticationSuccessHandler successHandler(JwtSecurityService jwtSecurityService, Dates dates,
                                                             CodecConfigurer configurer) {
        LocalDate now = dates.now().toLocalDate();
        //默认过期时间30天
        LocalDate expiredAt = now.plusDays(EXPIRES_DAYS);
        return (WebFilterExchange webFilterExchange, Authentication authentication) -> {
            UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) authentication;
            String jwtToken = jwtSecurityService.encode(token.getName(), token.getAuthorities(),
                    Date.from(now.atStartOfDay().atZone(ZoneId.systemDefault()).toInstant()),
                    Date.from(expiredAt.atStartOfDay().atZone(ZoneId.systemDefault()).toInstant()));
            ServerWebExchange exchange = webFilterExchange.getExchange();
            //取出来requestId，为了构建response
            String requestId = exchange.getRequest().getHeaders().get(RPCHttpHeaders.REQUEST_ID).get(0);
            return ServerResponse
                    .ok()
                    //返回token
                    .body(BodyInserters.fromObject(new AuthorizeResponse(requestId, RPCResponse.STATUS.OK, jwtToken)))
                    .flatMap((ServerResponse response) -> response.writeTo(exchange, new ServerResponse.Context() {
                        @Override
                        public List<HttpMessageWriter<?>> messageWriters() {
                            return configurer.getWriters();
                        }

                        @Override
                        public List<ViewResolver> viewResolvers() {
                            return Collections.emptyList();
                        }
                    }));
        };
    }

    //用户数据
    @Bean
    public UserDetailsRepositoryReactiveAuthenticationManager authenticationManager(
            ReactiveUserDetailsService userDetailsService) {
        return new UserDetailsRepositoryReactiveAuthenticationManager(userDetailsService);
    }

    //Mock 数据
    @Bean
    public MapReactiveUserDetailsService userDetailsService() {
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();
        //只有admin role 的话是不可以访问 user数据的，如果需要user的role，需要显式地加到roles里
        UserDetails admin = User.withDefaultPasswordEncoder()
                .username("admin")
                .password("password")
                .roles("ADMIN")
                .build();
        return new MapReactiveUserDetailsService(user, admin);
    }
}
