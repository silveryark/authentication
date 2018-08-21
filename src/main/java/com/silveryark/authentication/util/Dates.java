package com.silveryark.authentication.util;

import org.springframework.stereotype.Service;

import java.util.Date;

/**
 * 不要把所有有关时间的东西都放进来，这个类存在的意义在于做单元测试的时候可以mock出来这些可变的数据
 */
@Service
public class Dates {

    public Date now() {
        return new Date();
    }

    public Long currentMillis() {
        return System.currentTimeMillis();
    }
}
