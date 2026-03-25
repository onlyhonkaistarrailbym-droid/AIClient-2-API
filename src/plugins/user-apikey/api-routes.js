/**
 * 用户 API Key 插件 - API 路由
 */

import {
    registerUser, loginUser, logoutUser, verifyToken,
    getUser, listUsers, updateUserApiKey, getUserApiKeysMasked,
    adminUpdateUser, adminResetUsage, adminDeleteUser,
    changePassword, getGlobalStats, checkAndIncrementUsage
} from './user-manager.js';
import logger from '../../utils/logger.js';

// 【修复解析卡死】防止主程序先消耗了流，判断 req.body 与 req.complete
function parseBody(req) {
    return new Promise((resolve, reject) => {
        if (req.body) {
            return resolve(typeof req.body === 'string' ? JSON.parse(req.body) : req.body);
        }
        if (req.complete) {
            return resolve({}); // 数据流已被读取完
        }

        let body = '';
        req.on('data', c => body += c.toString());
        req.on('end', () => {
            try { resolve(body ? JSON.parse(body) : {}); }
            catch (e) { reject(new Error('Invalid JSON')); }
        });
        req.on('error', reject);
    });
}

function json(res, status, data) {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(data));
}

function extractToken(req) {
    const auth = req.headers.authorization;
    if (auth && auth.startsWith('Bearer ')) return auth.substring(7);
    return null;
}

function requireAuth(req) {
    const token = extractToken(req);
    if (!token) return null;
    return verifyToken(token);
}

function requireAdmin(req) {
    const user = requireAuth(req);
    if (!user || user.role !== 'admin') return null;
    return user;
}

// configGetter 由 plugin index 注入
let _configGetter = null;
export function setConfigGetter(fn) { _configGetter = fn; }

/**
 * 主路由处理器 - /api/uak/*
 */
export async function handleUserApiKeyRoutes(req, res) {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const pathname = url.pathname;
    const method = req.method.toUpperCase();

    try {
        // ── 公开接口 ──────────────────────────────────────────

        // 注册
        if (pathname === '/api/uak/register' && method === 'POST') {
            const { username, password, inviteCode } = await parseBody(req);
            const result = await registerUser(username, password, inviteCode, _configGetter);
            if (!result.success) {
                const messages = {
                    invalid_invite_code: '邀请码无效',
                    username_taken: '用户名已存在',
                    invalid_username: '用户名长度须为2~32位',
                    password_too_short: '密码至少6位',
                };
                return json(res, 400, { success: false, message: messages[result.reason] || '注册失败' });
            }
            return json(res, 200, { success: true, message: '注册成功' });
        }

        // 登录
        if (pathname === '/api/uak/login' && method === 'POST') {
            const { username, password } = await parseBody(req);
            const result = await loginUser(username, password);
            if (!result.success) {
                const messages = {
                    not_found: '用户不存在',
                    disabled: '账号已被禁用',
                    wrong_password: '密码错误',
                };
                return json(res, 401, { success: false, message: messages[result.reason] || '登录失败' });
            }
            return json(res, 200, { success: true, token: result.token, role: result.role });
        }

        // ── 用户接口（需登录）────────────────────────────────

        // 登出
        if (pathname === '/api/uak/logout' && method === 'POST') {
            const token = extractToken(req);
            if (token) await logoutUser(token);
            return json(res, 200, { success: true });
        }

        // 获取自己的信息
        if (pathname === '/api/uak/me' && method === 'GET') {
            const auth = requireAuth(req);
            if (!auth) return json(res, 401, { success: false, message: '未登录' });
            const user = getUser(auth.username);
            const apiKeysMasked = getUserApiKeysMasked(auth.username);
            return json(res, 200, { success: true, user: { ...user, apiKeysMasked } });
        }

        // 修改密码
        if (pathname === '/api/uak/change-password' && method === 'POST') {
            const auth = requireAuth(req);
            if (!auth) return json(res, 401, { success: false, message: '未登录' });
            const { oldPassword, newPassword } = await parseBody(req);
            const result = await changePassword(auth.username, oldPassword, newPassword);
            if (!result.success) {
                const messages = { wrong_password: '原密码错误', password_too_short: '新密码至少6位' };
                return json(res, 400, { success: false, message: messages[result.reason] || '修改失败' });
            }
            return json(res, 200, { success: true, message: '密码已更新' });
        }

        // 保存自己的 API Key
        if (pathname === '/api/uak/my-apikey' && method === 'PUT') {
            const auth = requireAuth(req);
            if (!auth) return json(res, 401, { success: false, message: '未登录' });
            const { provider, apiKey } = await parseBody(req);
            if (!provider) return json(res, 400, { success: false, message: '缺少 provider' });
            await updateUserApiKey(auth.username, provider, apiKey);
            return json(res, 200, { success: true, message: 'API Key 已保存' });
        }

        // ── 管理员接口 ────────────────────────────────────────

        // 获取所有用户
        if (pathname === '/api/uak/admin/users' && method === 'GET') {
            if (!requireAdmin(req)) return json(res, 403, { success: false, message: '需要管理员权限' });
            return json(res, 200, { success: true, users: listUsers() });
        }

        // 获取统计
        if (pathname === '/api/uak/admin/stats' && method === 'GET') {
            if (!requireAdmin(req)) return json(res, 403, { success: false, message: '需要管理员权限' });
            return json(res, 200, { success: true, stats: getGlobalStats() });
        }

        // 更新用户（额度/启用/角色）
        if (pathname.startsWith('/api/uak/admin/users/') && method === 'PATCH') {
            if (!requireAdmin(req)) return json(res, 403, { success: false, message: '需要管理员权限' });
            const username = decodeURIComponent(pathname.split('/')[5]);
            const updates = await parseBody(req);
            const result = await adminUpdateUser(username, updates);
            return json(res, result.success ? 200 : 404, result);
        }

        // 重置用量
        if (pathname.startsWith('/api/uak/admin/users/') && pathname.endsWith('/reset-usage') && method === 'POST') {
            if (!requireAdmin(req)) return json(res, 403, { success: false, message: '需要管理员权限' });
            const parts = pathname.split('/');
            const username = decodeURIComponent(parts[5]);
            const result = await adminResetUsage(username);
            return json(res, result.success ? 200 : 404, result);
        }

        // 删除用户
        if (pathname.startsWith('/api/uak/admin/users/') && method === 'DELETE') {
            if (!requireAdmin(req)) return json(res, 403, { success: false, message: '需要管理员权限' });
            const username = decodeURIComponent(pathname.split('/')[5]);
            const result = await adminDeleteUser(username);
            return json(res, result.success ? 200 : 404, result);
        }

        // 404
        return json(res, 404, { success: false, message: 'Not found in UAK Router' });

    } catch (e) {
        logger.error('[UserApiKey Routes] Error:', e.message);
        return json(res, 500, { success: false, message: '服务器错误: ' + e.message });
    }
}
