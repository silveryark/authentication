package com.silveryark.authentication;

import com.silveryark.security.resource.ResourceSecurity;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

//启动类，annotation的配置文件都放这里
@SpringBootApplication(scanBasePackages = "com.silveryark", exclude = ResourceSecurity.class)
public class AuthenticationApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthenticationApplication.class, args);
    }
}
