package local.ateng.boot.common.config.satoken;

import cn.dev33.satoken.context.SaHolder;
import cn.dev33.satoken.filter.SaServletFilter;
import cn.dev33.satoken.httpauth.basic.SaHttpBasicUtil;
import cn.dev33.satoken.interceptor.SaInterceptor;
import cn.dev33.satoken.router.SaRouter;
import cn.dev33.satoken.stp.StpUtil;
import cn.dev33.satoken.util.SaResult;
import cn.hutool.json.JSONUtil;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Sa-Token 注解鉴权
 * https://sa-token.cc/doc.html#/use/at-check
 *
 * @author 孔余
 * @since 2024-05-21 17:17
 */
@Configuration
public class SaTokenConfigure implements WebMvcConfigurer {
    // 注册 Sa-Token 拦截器，打开注解式鉴权功能
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        // 注册 Sa-Token 拦截器，打开注解式鉴权功能
        registry
                .addInterceptor(
                        new SaInterceptor(
                                handle -> StpUtil.checkLogin()
                        ).isAnnotation(true) // 注解鉴权
                )
                .addPathPatterns("/**")
                .excludePathPatterns("/actuator/**", "/demo/**")
        ;
    }

    /**
     * 注册 [Sa-Token 全局过滤器]
     */
    @Bean
    public FilterRegistrationBean<SaServletFilter> getSaServletFilter() {
        FilterRegistrationBean<SaServletFilter> frBean = new FilterRegistrationBean<>();
        frBean.setFilter(
                new SaServletFilter()
                        .addInclude("/actuator/**")
                        .setAuth(obj -> {
                            SaRouter
                                    .notMatch("/actuator/health")
                                    .match("/actuator/**", () -> SaHttpBasicUtil.check("admin:Admin@123"));
                        }).setError(e -> {
                            // 设置响应头
                            SaHolder.getResponse().setHeader("Content-Type", "application/json;charset=UTF-8");
                            // 使用封装的 JSON 工具类转换数据格式
                            return JSONUtil.toJsonStr(SaResult.error(e.getMessage()));
                        })
                        // 前置函数：在每次认证函数之前执行（BeforeAuth 不受 includeList 与 excludeList 的限制，所有请求都会进入）
                        .setBeforeAuth(r -> {
                            // ---------- 设置一些安全响应头 ----------
                            SaHolder.getResponse()
                                    // 服务器名称
                                    .setServer("sa-server")
                                    // 是否可以在iframe显示视图： DENY=不可以 | SAMEORIGIN=同域下可以 | ALLOW-FROM uri=指定域名下可以
                                    .setHeader("X-Frame-Options", "SAMEORIGIN")
                                    // 是否启用浏览器默认XSS防护： 0=禁用 | 1=启用 | 1; mode=block 启用, 并在检查到XSS攻击时，停止渲染页面
                                    .setHeader("X-XSS-Protection", "1; mode=block")
                                    // 禁用浏览器内容嗅探
                                    .setHeader("X-Content-Type-Options", "nosniff")
                            ;
                        })
        );
        frBean.setOrder(-101);  // 更改顺序为 -101
        return frBean;
    }

}




