/**
 * 用户 API Key 插件
 * 
 * 功能：
 * 1. 用户注册/登录（各自账号密码）
 * 2. 每个用户保存自己的真实 API Key
 * 3. 请求时自动使用该用户的 API Key 转发
 * 4. 每日请求额度限制
 * 5. 管理员可管理所有用户
 * 
 * 前端页面：
 * - /user-login.html   — 用户登录/注册
 * - /user-portal.html  — 用户个人中心（填 API Key、查用量）
 * - /user-admin.html   — 管理员用户管理
 */

import { verifyToken, getUserApiKey, checkAndIncrementUsage, promoteToAdmin } from './user-manager.js';
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

        // 如果插件配置了 adminUsername，自动提升为管理员
        const adminUsername = (_config.USER_APIKEY || {}).adminUsername;
        if (adminUsername) {
            const result = promoteToAdmin(adminUsername);
            if (result.success) {
                logger.info(`[UserApiKey Plugin] Promoted "${adminUsername}" to admin`);
            }
        }

        logger.info('[UserApiKey Plugin] Initialized');
    },

    async destroy() {
        logger.info('[UserApiKey Plugin] Destroyed');
    },

    staticPaths: ['user-login.html', 'user-portal.html', 'user-admin.html'],

    routes: [
        {
            method: '*',
            path: '/api/uak',
            handler: handleUserApiKeyRoutes,
        }
    ],

    /**
     * 认证方法 — 从请求头提取用户 token，验证身份，
     * 并将用户自己的真实 API Key 注入到 config 中供后续使用
     */
    async authenticate(req, res, requestUrl, config) {
        // 支持 Authorization: Bearer <token> 和 x-uak-token 头，以及 cookie
        let uakToken = req.headers['x-uak-token'] || parseCookieToken(req.headers['cookie']);

        // 同时支持标准 Authorization: Bearer 头
        // 关键：只处理 uak_ 开头的 token，其他 Bearer（如真实 API Key sk-ant-xxx）
        // 必须透传给 default-auth，否则会错误地拦截并返回 401
        if (!uakToken) {
            const auth = req.headers['authorization'];
            if (auth && auth.startsWith('Bearer ')) {
                const bearer = auth.substring(7);
                if (bearer.startsWith('uak_')) {
                    uakToken = bearer;
                }
            }
        }

        if (!uakToken) {
            // 不是本插件的请求，交给下一个插件
            return { handled: false, authorized: null };
        }

        const userInfo = verifyToken(uakToken);
        if (!userInfo) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: { message: '未登录或会话已过期，请重新在用户中心获取 Token', code: 'uak_unauthorized' } }));
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
