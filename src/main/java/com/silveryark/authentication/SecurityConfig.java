package com.silveryark.authentication;

import com.silveryark.authentication.util.Dates;
import com.silveryark.rpc.RPCHttpHeaders;
import com.silveryark.rpc.RPCResponse;
import com.silveryark.rpc.authentication.AuthorizeRequest;
import com.silveryark.rpc.authorize.AuthorizeResponse;
import com.silveryark.security.JwtSecurityService;
import org.apache.commons.lang3.time.DateUtils;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.http.codec.HttpMessageWriter;
import org.springframework.http.codec.ServerCodecConfigurer;
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.server.SecurityWebFilterChain;
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

import java.util.Date;
import java.util.List;

@EnableWebFluxSecurity
public class SecurityConfig {

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
            ServerCodecConfigurer configurer,
            ServerAuthenticationSuccessHandler successHandler,
            ServerAuthenticationFailureHandler failureHandler) {
        AuthenticationWebFilter authenticationWebFilter = new AuthenticationWebFilter(reactiveAuthenticationManager);
        authenticationWebFilter.setAuthenticationConverter((ServerWebExchange exchange) -> {
            //这里使用 ServerRequest，就可以直接使用BodyExtractor来处理信息，否则还要根据http header来判断数据格式，
            ServerRequest serverRequest = ServerRequest.create(exchange, configurer.getReaders());
            Mono<AuthorizeRequest> authorizeRequestMono = serverRequest.body(BodyExtractors.toMono(AuthorizeRequest.class));
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

    @Bean
    public ServerAuthenticationFailureHandler failureHandler(ServerCodecConfigurer configurer) {
        return ((webFilterExchange, exception) -> {
            ServerWebExchange exchange = webFilterExchange.getExchange();
            //取出来requestId，为了构建response
            String requestId = exchange.getRequest().getHeaders().get(RPCHttpHeaders.REQUEST_ID).get(0);
            return ServerResponse
                    .ok()
                    .body(BodyInserters.fromObject(new AuthorizeResponse(requestId, RPCResponse.STATUS.OK,
                            exception)))
                    .flatMap((ServerResponse response) -> response.writeTo(exchange, new ServerResponse.Context() {
                        @Override
                        public List<HttpMessageWriter<?>> messageWriters() {
                            return configurer.getWriters();
                        }

                        @Override
                        public List<ViewResolver> viewResolvers() {
                            return null;
                        }
                    }));
        });
    }

    //把成功认证的信息写到输出里（返回 jwtToken）
    @Bean
    public ServerAuthenticationSuccessHandler successHandler(JwtSecurityService jwtSecurityService, Dates dates,
                                                             ServerCodecConfigurer configurer) {
        Date now = dates.now();
        Date expiredAt = DateUtils.addDays(now, 30);
        return (webFilterExchange, authentication) -> {
            UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) authentication;
            String jwtToken = jwtSecurityService.encode(token.getName(), token.getAuthorities(), now, expiredAt);
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
                            return null;
                        }
                    }));
        };
    }

    //用户数据
    @Bean
    public UserDetailsRepositoryReactiveAuthenticationManager authenticationManager(ReactiveUserDetailsService userDetailsService) {
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
        UserDetails admin = User.withDefaultPasswordEncoder()
                .username("admin")
                .password("password")
                .roles("ADMIN")
                .build();
        return new MapReactiveUserDetailsService(user, admin);
    }
}
