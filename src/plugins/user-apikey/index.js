/**
 * 用户 API Key 插件
 * * 功能：
 * 1. 用户注册/登录（各自账号密码）
 * 2. 每个用户保存自己的真实 API Key
 * 3. 请求时自动使用该用户的 API Key 转发
 * 4. 每日请求额度限制
 * 5. 管理员可管理所有用户
 * * 前端页面：
 * - /user-login.html   — 用户登录/注册
 * - /user-portal.html  — 用户个人中心（填 API Key、查用量）
 * - /user-admin.html   — 管理员用户管理
 */

import { verifyToken, getUserApiKey, checkAndIncrementUsage } from './user-manager.js';
import { handleUserApiKeyRoutes, setConfigGetter } from './api-routes.js';
import logger from '../../utils/logger.js';

let _config = {};

const userApiKeyPlugin = {
    name: 'user-apikey',
    version: '1.0.0',
    description: '用户自带 API Key 插件 — 用户注册登录并填写自己的 API Key，支持每日额度限制<br>登录页：<a href="user-login.html" target="_blank">user-login.html</a><br>用户中心：<a href="user-portal.html" target="_blank">user-portal.html</a><br>管理员：<a href="user-admin.html" target="_blank">user-admin.html</a>',

    type: 'auth',
    _priority: 8, // 比 api-potluck (10) 更早执行

    async init(config) {
        _config = config;
        setConfigGetter(() => _config.USER_APIKEY || {});
        logger.info('[UserApiKey Plugin] Initialized');
    },

    async destroy() {
        logger.info('[UserApiKey Plugin] Destroyed');
    },

    staticPaths: ['user-login.html', 'user-portal.html', 'user-admin.html'],

    // 【修复路由匹配】兼容不同代理版本的正则与绝对路径匹配
    routes: [
        { method: '*', path: /^\/api\/uak(\/.*)?$/, handler: handleUserApiKeyRoutes },
        // 兜底方案，防止代理核心不支持正则
        { method: 'POST', path: '/api/uak/register', handler: handleUserApiKeyRoutes },
        { method: 'POST', path: '/api/uak/login', handler: handleUserApiKeyRoutes },
        { method: 'POST', path: '/api/uak/logout', handler: handleUserApiKeyRoutes },
        { method: 'GET', path: '/api/uak/me', handler: handleUserApiKeyRoutes },
        { method: 'POST', path: '/api/uak/change-password', handler: handleUserApiKeyRoutes },
        { method: 'PUT', path: '/api/uak/my-apikey', handler: handleUserApiKeyRoutes },
        { method: 'GET', path: '/api/uak/admin/users', handler: handleUserApiKeyRoutes },
        { method: 'GET', path: '/api/uak/admin/stats', handler: handleUserApiKeyRoutes }
    ],

    /**
     * 认证方法 — 从请求头提取用户 token，验证身份，
     * 并将用户自己的真实 API Key 注入到 config 中供后续使用
     */
    async authenticate(req, res, requestUrl, config) {
        // 优先从 x-uak-token 头获取，也支持 cookie
        const uakToken = req.headers['x-uak-token']
            || parseCookieToken(req.headers['cookie']);

        if (!uakToken) {
            // 不是本插件的请求，交给下一个插件
            return { handled: false, authorized: null };
        }

        const userInfo = verifyToken(uakToken);
        if (!userInfo) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: { message: '未登录或会话已过期', code: 'uak_unauthorized' } }));
            return { handled: true, authorized: false };
        }

        // 检查额度（管理员不限）
        if (userInfo.role !== 'admin') {
            const ok = checkAndIncrementUsage(userInfo.username);
            if (!ok) {
                res.writeHead(429, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: { message: '今日请求额度已用完', code: 'uak_quota_exceeded' } }));
                return { handled: true, authorized: false };
            }
        }

        // 获取该用户保存的真实 API Key，注入到 config 中
        // 优先从请求头 x-uak-provider 获取 provider，否则使用当前配置的 provider
        const provider = req.headers['x-uak-provider'] || config.MODEL_PROVIDER;
        const userKey = getUserApiKey(userInfo.username, provider);

        logger.info(`[UserApiKey Plugin] Authorized user: ${userInfo.username} (${userInfo.role}), provider: ${provider}, hasKey: ${!!userKey}`);

        return {
            handled: false,
            authorized: true,
            data: {
                uakUsername: userInfo.username,
                uakRole: userInfo.role,
                // 如果用户有自己的 key，覆盖全局 key
                ...(userKey ? { injectedApiKey: userKey } : {}),
            }
        };
    },

    hooks: {
        // 如果有注入的 API Key，在请求发出前替换掉全局 key
        async onBeforeRequest(hookContext) {
            if (hookContext.injectedApiKey) {
                hookContext.apiKey = hookContext.injectedApiKey;
            }
        }
    }
};

function parseCookieToken(cookieHeader) {
    if (!cookieHeader) return null;
    const match = cookieHeader.match(/uak_token=([^;]+)/);
    return match ? match[1] : null;
}

export default userApiKeyPlugin;
