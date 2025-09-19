package com.github.nogueiralegacy.truststore;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class Teste {

    @Scheduled(fixedRate = 1000 * 60 * 60 * 2)
    public void scheduleFixedDelayTask() {
        System.out.println(
                "Fixed delay task - " + System.currentTimeMillis());
    }
}
