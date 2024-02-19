package com.zlx.zlxgateway;

import com.zlx.zlxclientsdk.utils.SignUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.List;

/**
 * 全局过滤器
 */
@Component
@Slf4j
public class CustomGlobalFilter implements GlobalFilter, Ordered {

    private static final List<String> IP_WHITE_LIST = Arrays.asList("127.0.0.1");
    private static final Long FIVE_MINUTES = 5 * 60L;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        //1. 用户发送请求到API网关
        //2. 请求日志
        ServerHttpRequest request = exchange.getRequest();
        log.info("唯一标识" + request.getId());
        log.info("请求路径" + request.getPath().value());
        log.info("请求方法" + request.getMethod());
        log.info("请求参数" + request.getQueryParams());
        String hostString = request.getLocalAddress().getHostString();
        log.info("请求来源地址" + hostString);
        log.info("请求来源地址" + request.getRemoteAddress());
        ServerHttpResponse response = exchange.getResponse();
        //3. （黑白名单）
        if (!IP_WHITE_LIST.contains(hostString)) {
            // 状态设置为403 禁止访问
            response.setStatusCode(HttpStatus.FORBIDDEN);
            return response.setComplete();
        }
        //4. 用户鉴权（判断ak,sk是否合法）;
        HttpHeaders headers = request.getHeaders();
        String accessKey = headers.getFirst("accessKey");
        String nonce = headers.getFirst("nonce");
        String timestamp = headers.getFirst("timestamp");
        String sign = headers.getFirst("sign");
        String body = headers.getFirst("body");
//        // todo 实际情况应该是去数据库中查是否已分配给用户
        if (!accessKey.equals("zlx")) {
            return handleNoAuth(response);
        }
        if (Long.parseLong(nonce) > 10000) {
            return handleNoAuth(response);
        }
        // todo 时间和当前时间不能超过 5 分钟
        long currentTime = System.currentTimeMillis() / 1000;
        if ((currentTime - Long.parseLong(timestamp)) >= FIVE_MINUTES) {
            return handleNoAuth(response);
        }
        // todo 实际情况中是从数据库中查出 secretKey
        String serverSign = SignUtils.genSign(body, "abcdefgh");
        if (!sign.equals(serverSign)) {
            return handleNoAuth(response);
        }
        //5. 请求的模拟接口是否存在;
        Mono<Void> filter = chain.filter(exchange);
        //6. 请求转发，请求模拟接口;
        log.info("响应" + response.getStatusCode());
        //7. 响应日志;
        if (response.getStatusCode() == HttpStatus.OK) {

        }else {
            return handleInvokeError(response);
        }
        //8. 调用成功，接口调用次数+1;
        //9. 调用失败，返回一个规范的错误码
        log.info("custom global filter");
        return filter;
    }

    @Override
    public int getOrder() {
        return -1;
    }

    public Mono<Void> handleNoAuth(ServerHttpResponse response){
        response.setStatusCode(HttpStatus.FORBIDDEN);
        return response.setComplete();
    }

    public Mono<Void> handleInvokeError(ServerHttpResponse response){
        response.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
        return response.setComplete();
    }
}