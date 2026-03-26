/**
 * 用户 API Key 插件 - API 路由 v2
 */

import {
    registerUser, loginUser, logoutUser, verifyToken,
    getUser, listUsers, updateUserApiKey, getUserApiKeysMasked,
    adminUpdateUser, adminResetUsage, adminDeleteUser,
    changePassword, getGlobalStats, checkAndIncrementUsage,
    getSystemSettings, updateSystemSettings,
    listInviteCodes, createInviteCode, deleteInviteCode,
    listAnnouncements, createAnnouncement, updateAnnouncement, deleteAnnouncement,
} from './user-manager.js';
import logger from '../../utils/logger.js';

// configGetter 供 index.js 注入，让路由模块可以读取插件配置
let _configGetter = () => ({});
export function setConfigGetter(fn) { _configGetter = fn; }

function parseBody(req) {
    return new Promise((resolve, reject) => {
        let body = '';
        req.on('data', c => body += c.toString());
        req.on('end', () => { try { resolve(body ? JSON.parse(body) : {}); } catch(e) { reject(new Error('Invalid JSON')); } });
        req.on('error', reject);
    });
}

function json(res, status, data) {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(data));
}

function extractToken(req) {
    const auth = req.headers.authorization;
    return auth && auth.startsWith('Bearer ') ? auth.substring(7) : null;
}

function requireAuth(req)  { const t = extractToken(req); return t ? verifyToken(t) : null; }
function requireAdmin(req) { const u = requireAuth(req); return u?.role === 'admin' ? u : null; }

export async function handleUserApiKeyRoutes(method, path, req, res) {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const pathname = url.pathname;

    try {

        // ── 公开接口 ────────────────────────────────────────────

        // 获取注册状态（登录页用）
        if (pathname === '/api/uak/register-status' && method === 'GET') {
            const s = getSystemSettings();
            return json(res, 200, { success: true, registerOpen: s.registerOpen, requireInviteCode: s.requireInviteCode });
        }

        // 注册
        if (pathname === '/api/uak/register' && method === 'POST') {
            const { username, password, inviteCode } = await parseBody(req);
            const result = await registerUser(username, password, inviteCode);
            if (!result.success) {
                const msgs = {
                    register_closed:    '注册暂已关闭，请联系管理员',
                    invite_required:    '注册需要邀请码',
                    invalid_invite_code:'邀请码无效',
                    invite_used_up:     '邀请码已达使用上限',
                    username_taken:     '用户名已存在',
                    invalid_username:   '用户名须为2~32位，只含字母数字下划线或中文',
                    password_too_short: '密码至少6位',
                };
                return json(res, 400, { success: false, message: msgs[result.reason] || '注册失败' });
            }
            return json(res, 200, { success: true, message: result.role === 'admin' ? '欢迎！首个账号已设为管理员' : '注册成功', isFirstAdmin: result.role === 'admin' });
        }

        // 登录
        if (pathname === '/api/uak/login' && method === 'POST') {
            const { username, password } = await parseBody(req);
            const result = await loginUser(username, password);
            if (!result.success) {
                const msgs = { not_found: '用户不存在', disabled: '账号已被禁用', wrong_password: '密码错误' };
                return json(res, 401, { success: false, message: msgs[result.reason] || '登录失败' });
            }
            return json(res, 200, { success: true, token: result.token, role: result.role });
        }

        // 获取公告（用户可读）
        if (pathname === '/api/uak/announcements' && method === 'GET') {
            requireAuth(req); // 不强制，未登录也能看
            return json(res, 200, { success: true, announcements: listAnnouncements(true) });
        }

        // ── 用户接口（需登录）──────────────────────────────────

        if (pathname === '/api/uak/logout' && method === 'POST') {
            await logoutUser(extractToken(req));
            return json(res, 200, { success: true });
        }

        if (pathname === '/api/uak/me' && method === 'GET') {
            const auth = requireAuth(req);
            if (!auth) return json(res, 401, { success: false, message: '未登录' });
            const user = getUser(auth.username);
            return json(res, 200, { success: true, user: { ...user, apiKeysMasked: getUserApiKeysMasked(auth.username) } });
        }

        if (pathname === '/api/uak/change-password' && method === 'POST') {
            const auth = requireAuth(req);
            if (!auth) return json(res, 401, { success: false, message: '未登录' });
            const { oldPassword, newPassword } = await parseBody(req);
            const result = await changePassword(auth.username, oldPassword, newPassword);
            if (!result.success) {
                const msgs = { wrong_password: '原密码错误', password_too_short: '新密码至少6位' };
                return json(res, 400, { success: false, message: msgs[result.reason] || '修改失败' });
            }
            return json(res, 200, { success: true, message: '密码已更新' });
        }

        if (pathname === '/api/uak/my-apikey' && method === 'PUT') {
            const auth = requireAuth(req);
            if (!auth) return json(res, 401, { success: false, message: '未登录' });
            const { provider, apiKey } = await parseBody(req);
            if (!provider) return json(res, 400, { success: false, message: '缺少 provider' });
            await updateUserApiKey(auth.username, provider, apiKey);
            return json(res, 200, { success: true });
        }

        // ── 管理员接口 ─────────────────────────────────────────

        // 用户列表 & 统计
        if (pathname === '/api/uak/admin/users' && method === 'GET') {
            if (!requireAdmin(req)) return json(res, 403, { success: false, message: '需要管理员权限' });
            return json(res, 200, { success: true, users: listUsers() });
        }

        if (pathname === '/api/uak/admin/stats' && method === 'GET') {
            if (!requireAdmin(req)) return json(res, 403, { success: false, message: '需要管理员权限' });
            return json(res, 200, { success: true, stats: getGlobalStats() });
        }

        // 编辑用户
        if (pathname.startsWith('/api/uak/admin/users/') && !pathname.endsWith('/reset-usage') && method === 'PATCH') {
            if (!requireAdmin(req)) return json(res, 403, { success: false, message: '需要管理员权限' });
            const username = decodeURIComponent(pathname.split('/')[5]);
            const result = await adminUpdateUser(username, await parseBody(req));
            return json(res, result.success ? 200 : 404, result);
        }

        // 重置用量
        if (pathname.startsWith('/api/uak/admin/users/') && pathname.endsWith('/reset-usage') && method === 'POST') {
            if (!requireAdmin(req)) return json(res, 403, { success: false, message: '需要管理员权限' });
            const username = decodeURIComponent(pathname.split('/')[5]);
            return json(res, 200, await adminResetUsage(username));
        }

        // 删除用户
        if (pathname.startsWith('/api/uak/admin/users/') && method === 'DELETE') {
            if (!requireAdmin(req)) return json(res, 403, { success: false, message: '需要管理员权限' });
            const username = decodeURIComponent(pathname.split('/')[5]);
            return json(res, 200, await adminDeleteUser(username));
        }

        // ── 系统设置 ───────────────────────────────────────────

        if (pathname === '/api/uak/admin/settings' && method === 'GET') {
            if (!requireAdmin(req)) return json(res, 403, { success: false, message: '需要管理员权限' });
            return json(res, 200, { success: true, settings: getSystemSettings() });
        }

        if (pathname === '/api/uak/admin/settings' && method === 'PATCH') {
            if (!requireAdmin(req)) return json(res, 403, { success: false, message: '需要管理员权限' });
            return json(res, 200, await updateSystemSettings(await parseBody(req)));
        }

        // ── 邀请码 ─────────────────────────────────────────────

        if (pathname === '/api/uak/admin/invite-codes' && method === 'GET') {
            if (!requireAdmin(req)) return json(res, 403, { success: false, message: '需要管理员权限' });
            return json(res, 200, { success: true, codes: listInviteCodes() });
        }

        if (pathname === '/api/uak/admin/invite-codes' && method === 'POST') {
            if (!requireAdmin(req)) return json(res, 403, { success: false, message: '需要管理员权限' });
            const { note, usageLimit } = await parseBody(req);
            return json(res, 200, await createInviteCode(note, usageLimit));
        }

        if (pathname.startsWith('/api/uak/admin/invite-codes/') && method === 'DELETE') {
            if (!requireAdmin(req)) return json(res, 403, { success: false, message: '需要管理员权限' });
            const code = decodeURIComponent(pathname.split('/')[5]);
            return json(res, 200, await deleteInviteCode(code));
        }

        // ── 公告 ───────────────────────────────────────────────

        if (pathname === '/api/uak/admin/announcements' && method === 'GET') {
            if (!requireAdmin(req)) return json(res, 403, { success: false, message: '需要管理员权限' });
            return json(res, 200, { success: true, announcements: listAnnouncements(false) });
        }

        if (pathname === '/api/uak/admin/announcements' && method === 'POST') {
            if (!requireAdmin(req)) return json(res, 403, { success: false, message: '需要管理员权限' });
            const { content, pinned } = await parseBody(req);
            return json(res, 200, await createAnnouncement(content, pinned));
        }

        if (pathname.startsWith('/api/uak/admin/announcements/') && method === 'PATCH') {
            if (!requireAdmin(req)) return json(res, 403, { success: false, message: '需要管理员权限' });
            const id = decodeURIComponent(pathname.split('/')[5]);
            return json(res, 200, await updateAnnouncement(id, await parseBody(req)));
        }

        if (pathname.startsWith('/api/uak/admin/announcements/') && method === 'DELETE') {
            if (!requireAdmin(req)) return json(res, 403, { success: false, message: '需要管理员权限' });
            const id = decodeURIComponent(pathname.split('/')[5]);
            return json(res, 200, await deleteAnnouncement(id));
        }

        return json(res, 404, { success: false, message: 'Not found' });

    } catch(e) {
        logger.error('[UserApiKey Routes] Error:', e.message);
        return json(res, 500, { success: false, message: '服务器错误' });
    }
}
