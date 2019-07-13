package com.bsport.gateway.filters;

import com.bsport.common.constant.Constant;
import com.bsport.common.exception.CommonException;
import com.bsport.common.model.auth.Role;
import com.bsport.common.model.auth.Token;
import com.bsport.common.model.user.User;
import com.bsport.gateway.service.ValidateService;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.springframework.cloud.netflix.zuul.filters.support.FilterConstants.*;

/**
 * Created by IntelliJ IDEA.
 * User: Truong Nguyen
 * Date: 17-Dec-18
 * Time: 10:13 AM
 * To change this template use File | Settings | File Templates.
 */
public class AuthenticationPreFilter extends ZuulFilter {
    private static final Logger LOGGER = LogManager.getLogger(Constant.LOG_APPENDER.AUTHENTICATION);

    @Autowired
    ValidateService validateService;

    @Override
    public int filterOrder() {
        return PRE_DECORATION_FILTER_ORDER - 1; // run before PreDecoration
    }

    @Override
    public String filterType() {
        return PRE_TYPE;
    }

    @Override
    public boolean shouldFilter() {
        RequestContext ctx = RequestContext.getCurrentContext();
        return !ctx.containsKey(FORWARD_TO_KEY) // a filter has already forwarded
                && !ctx.containsKey(SERVICE_ID_KEY); // a filter has already determined serviceId
    }

    @Override
    public Object run() {
        RequestContext ctx = RequestContext.getCurrentContext();
        HttpServletRequest request = ctx.getRequest();
        String jwtFromRequest = getJwtFromRequest(request);
        String uri = request.getRequestURI();
        String method = request.getMethod();
        int status = HttpStatus.OK.value();
        String err = HttpStatus.OK.getReasonPhrase();
        long id = System.currentTimeMillis();
        LOGGER.info("[B][" + id + "] preHandle " + method + " > " + uri + " > " + jwtFromRequest);
        try {
            //Bo qua nhung api call den voi method = OPTIONS
            if (validateService.ignoredMethod(method))
                return null;
            //Bo qua nhung api call den micro-service sso
            if (validateService.ignoredUri(uri))
                return null;
            Token token = validateService.validateToken(jwtFromRequest);
            User user = validateService.validateUser(token.getUserId());
            Role role = new Role(method, uri);
            Role roleCache = validateService.validateRole(role);
            if (!validateService.ignoredUri(user.getId(), roleCache.getId())) {
                return null;
            }
        } catch (CommonException e) {
            LOGGER.error("[CommonException] when preHandle >>> " + e.toString());
            /*Commen tam lai de k bi validate - Trien khai hoac muon validate role thi bo ra
            err = e.getMessage();
            status = e.getResponse().getStatus().value();
            setFailedRequest(err, status);
            */
            return null;
        } catch (Exception e) {
            LOGGER.error("[Exception] when preHandle ", e);
            err = ("Exception when preHandle " + e.getMessage());
            status = HttpStatus.INTERNAL_SERVER_ERROR.value();
            setFailedRequest(err, status);
            return null;
        } finally {
            LOGGER.info("[E][" + id + "][Duration = " + (System.currentTimeMillis() - id) + "] preHandle " + status + " > " + err);
        }
        return null;
    }

    /**
     * Reports an error message given a response body and code.
     *
     * @param body
     * @param code
     */
    private void setFailedRequest(String body, int code) {
        RequestContext ctx = RequestContext.getCurrentContext();
        HttpServletResponse response = ctx.getResponse();
        ctx.setResponseStatusCode(code);
        if (ctx.getResponseBody() == null) {
            response.setContentType("text/plain; charset=UTF-8");
            ctx.setResponseBody(body);
            ctx.setSendZuulResponse(false);
        }
    }

    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

}
