package com.bsport.gateway.thread;

import com.bsport.common.cache.CacheService;
import com.bsport.common.constant.Constant;
import com.bsport.common.feign.AuthServiceFeignAPI;
import com.bsport.common.feign.CategoryServiceFeignAPI;
import com.bsport.common.model.auth.Role;
import com.bsport.common.model.auth.Token;
import com.bsport.common.util.ArrayListCommon;
import com.bsport.common.util.JsonCommon;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

@Service
public class DataAccess {
    private static final Logger LOGGER = LogManager.getLogger(DataAccess.class);

    @Autowired
    CacheService cacheService;

    @Autowired
    AuthServiceFeignAPI authServiceFeignAPI;

    @Autowired
    CategoryServiceFeignAPI categoryServiceFeignAPI;

    ExecutorService executorService;

    @PostConstruct
    public void init() {
        int numThreads = cacheService.getIntParamFromCache(Constant.PARAMS.TYPE.NUM_THREADS, Constant.FEIGN_CLIENT.SERVICE_SSO, 100);
        executorService = Executors.newFixedThreadPool(numThreads);
    }

    public void saveRole(Role role) {
        executorService.execute(new Runnable() {
            @Override
            public void run() {
                long id = System.currentTimeMillis();
                LOGGER.info("[B][" + id + "] saveRole " + JsonCommon.objectToJsonNotNull(role));
                try {
                    authServiceFeignAPI.create(role);
                } catch (Exception e) {
                    LOGGER.info("[Exception][" + id + "] when saveRole ", e);
                } finally {
                    LOGGER.info("[E][" + id + "][Duration = " + (System.currentTimeMillis() - id) + "] saveRole");
                }
            }
        });
    }

    public void reloadRoleOfUser(long userId) {
        executorService.execute(new Runnable() {
            @Override
            public void run() {
                long id = System.currentTimeMillis();
                LOGGER.info("[B][" + id + "] reloadRoleOfUser " + userId);
                try {
                    List<Role> roleList = authServiceFeignAPI.findAllRoleByUserId(userId);
                    if (!ArrayListCommon.isNullOrEmpty(roleList))
                        cacheService.setUserRoleRedisCache(userId, roleList, 365, TimeUnit.DAYS);
                } catch (Exception e) {
                    LOGGER.info("[Exception][" + id + "] when reloadRoleOfUser ", e);
                } finally {
                    LOGGER.info("[E][" + id + "][Duration = " + (System.currentTimeMillis() - id) + "] reloadRoleOfUser");
                }
            }
        });
    }

    public void addToken2Cache(Token token) {
        executorService.execute(new Runnable() {
            @Override
            public void run() {
                long id = System.currentTimeMillis();
                LOGGER.info("[B][" + id + "] addToken2Cache " + JsonCommon.objectToJsonNotNull(token));
                try {
                    cacheService.addToken2RedisCache(token, token.getExpiration(), TimeUnit.MILLISECONDS);
                } catch (Exception e) {
                    LOGGER.info("[Exception][" + id + "] when addToken2Cache ", e);
                } finally {
                    LOGGER.info("[E][" + id + "][Duration = " + (System.currentTimeMillis() - id) + "] addToken2Cache");
                }
            }
        });
    }
}
