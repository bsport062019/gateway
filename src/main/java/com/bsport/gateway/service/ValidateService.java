package com.bsport.gateway.service;

import com.bsport.common.model.auth.Role;
import com.bsport.common.model.auth.Token;
import com.bsport.common.model.user.User;
import org.springframework.stereotype.Service;

/**
 * Created by IntelliJ IDEA.
 *
 * @author: truongnq
 * @date: 28-Mar-19 4:20 PM
 * To change this template use File | Settings | File Templates.
 */
@Service
public interface ValidateService {
    Token validateToken(String token) throws Exception;

    User validateUser(long userId) throws Exception;

    Role validateRole(Role role) throws Exception;

    boolean ignoredUri(long userId, long roleId);

    boolean ignoredUri(String uri);

    boolean ignoredMethod(String method);
}
