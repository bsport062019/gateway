package com.bsport.gateway.service;

import com.bsport.common.cache.CacheService;
import com.bsport.common.constant.Constant;
import com.bsport.common.exception.CommonException;
import com.bsport.common.message.MessageCommon;
import com.bsport.common.model.auth.Role;
import com.bsport.common.model.auth.Token;
import com.bsport.common.model.user.User;
import com.bsport.common.response.Response;
import com.bsport.common.util.ResourceCommon;
import com.bsport.common.util.StringCommon;
import com.bsport.gateway.thread.DataAccess;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestMethod;

/**
 * Created by IntelliJ IDEA.
 *
 * @author: truongnq
 * @date: 28-Mar-19 4:20 PM
 * To change this template use File | Settings | File Templates.
 */
@Service
public class ValidateServiceImpl implements ValidateService {

    @Autowired
    DataAccess dataAccess;
    @Autowired
    CacheService cacheService;

    @Override
    public Token validateToken(String jwtFromRequest) throws Exception {
        if (StringCommon.isNullOrBlank(jwtFromRequest))
            throw new CommonException(Response.BAD_REQUEST, MessageCommon.getMessage(ResourceCommon.getMessageResource(Constant.RESOURCE.KEY.IS_NULL), Constant.TABLE.TOKEN));
        Token token = cacheService.getTokenFromCache(jwtFromRequest);
        if (token == null || token.getUserId() == null)
            throw new CommonException(Response.UNAUTHORIZED, MessageCommon.getMessage(ResourceCommon.getMessageResource(Constant.RESOURCE.KEY.NOT_AVAILABLE), Constant.TABLE.TOKEN));
        dataAccess.addToken2Cache(token);
        return token;
    }

    @Override
    public User validateUser(long userId) throws Exception {
        User user = cacheService.getUserFromToken(userId);
        if (user == null)
            throw new CommonException(Response.INVALID_PERMISSION, MessageCommon.getMessage(ResourceCommon.getMessageResource(Constant.RESOURCE.KEY.NOT_FOUND_FIELD_OF_OBJECT), userId + "", Constant.TABLE.USER));
        if (user.getStatus() == null || user.getStatus() != Constant.STATUS_OBJECT.ACTIVE)
            throw new CommonException(Response.INVALID_PERMISSION, MessageCommon.getMessage(ResourceCommon.getMessageResource(Constant.RESOURCE.KEY.INACTIVE_FIELD_OF_OBJECT), userId + "", Constant.TABLE.USER));
        if (user.getEmailVerified() == null || user.getEmailVerified() != Constant.STATUS_OBJECT.ACTIVE)
            throw new CommonException(Response.INVALID_PERMISSION, "User " + user.getEmail() + " chưa được xác thực email. Vui lòng check email và click vào link như đã hướng dẫn.");
        return user;
    }

    @Override
    public Role validateRole(Role role) throws Exception {
        Role roleCache = cacheService.getRoleFromCache(role.getCode());
        if (roleCache == null) {
            //Tao moi luon role nay va add vao redisCache
            dataAccess.saveRole(role);
            throw new CommonException(Response.METHOD_NOT_ALLOWED, MessageCommon.getMessage(ResourceCommon.getMessageResource(Constant.RESOURCE.KEY.NOT_FOUND_FIELD_OF_OBJECT), role.getCode(), Constant.TABLE.ROLE));
        }
        if (roleCache.getId() == null || roleCache.getStatus() == null || roleCache.getStatus() != Constant.STATUS_OBJECT.ACTIVE) {
            //Tao moi luon role nay va add vao redisCache
            dataAccess.saveRole(role);
            throw new CommonException(Response.METHOD_NOT_ALLOWED, MessageCommon.getMessage(ResourceCommon.getMessageResource(Constant.RESOURCE.KEY.INVALID_FIELD_OF_OBJECT), role.getCode(), Constant.TABLE.ROLE));
        }
        return roleCache;
    }

    @Override
    public boolean ignoredUri(long userId, long roleId) {
        if (!(cacheService.getUserRoleFromCache(userId, roleId) == Constant.STATUS_OBJECT.ACTIVE)) {
            //Reload lai quyen cho user
            dataAccess.reloadRoleOfUser(userId);
            throw new CommonException(Response.METHOD_NOT_ALLOWED, "User " + userId + " khong co quyen " + roleId);
        }
        return true;
    }

    @Override
    public boolean ignoredUri(String uri) {
        return uri.toLowerCase().contains("/api/sso")
//                || uri.toLowerCase().contains("/api/category")
//                || uri.toLowerCase().contains("/api/auth")
//                || uri.toLowerCase().contains("/api/core")
//                || uri.toLowerCase().contains("/api/schedule")
                || uri.toLowerCase().contains("/ping");
    }

    @Override
    public boolean ignoredMethod(String method) {
        return method.equals(RequestMethod.OPTIONS.name());
    }
}
