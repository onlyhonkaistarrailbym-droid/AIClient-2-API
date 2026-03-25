/**
 * 用户 API Key 插件 - 用户管理模块
 * 每个用户有自己的账号、密码、API key 和每日额度
 */

import { promises as fs } from 'fs';
import { existsSync, readFileSync, writeFileSync } from 'fs';
import path from 'path';
import crypto from 'crypto';
import logger from '../../utils/logger.js';

const USERS_STORE_FILE = path.join(process.cwd(), 'configs', 'user-apikey-users.json');
const TOKEN_STORE_FILE = path.join(process.cwd(), 'configs', 'user-apikey-tokens.json');

const DEFAULT_DAILY_LIMIT = 200; // 普通用户默认每日额度

// ─── 内存缓存 ────────────────────────────────────────────────
let userStore = null;
let tokenStore = null;
let isDirty = false;
let persistTimer = null;

function ensureLoaded() {
    if (userStore !== null) return;
    try {
        userStore = existsSync(USERS_STORE_FILE)
            ? JSON.parse(readFileSync(USERS_STORE_FILE, 'utf8'))
            : { users: {} };
    } catch (e) {
        logger.error('[UserApiKey] Failed to load user store:', e.message);
        userStore = { users: {} };
    }

    try {
        tokenStore = existsSync(TOKEN_STORE_FILE)
            ? JSON.parse(readFileSync(TOKEN_STORE_FILE, 'utf8'))
            : { tokens: {} };
    } catch (e) {
        tokenStore = { tokens: {} };
    }

    if (!persistTimer) {
        persistTimer = setInterval(persistIfDirty, 5000);
        process.on('beforeExit', persistSync);
        process.on('SIGINT', () => { persistSync(); process.exit(0); });
        process.on('SIGTERM', () => { persistSync(); process.exit(0); });
    }
}

async function persistIfDirty() {
    if (!isDirty) return;
    isDirty = false;
    try {
        await fs.writeFile(USERS_STORE_FILE, JSON.stringify(userStore, null, 2), 'utf8');
        await fs.writeFile(TOKEN_STORE_FILE, JSON.stringify(tokenStore, null, 2), 'utf8');
    } catch (e) {
        logger.error('[UserApiKey] Failed to persist:', e.message);
    }
}

function persistSync() {
    if (!isDirty) return;
    try {
        writeFileSync(USERS_STORE_FILE, JSON.stringify(userStore, null, 2), 'utf8');
        writeFileSync(TOKEN_STORE_FILE, JSON.stringify(tokenStore, null, 2), 'utf8');
    } catch (e) { /* ignore */ }
}

function markDirty() { isDirty = true; }

// ─── 工具函数 ────────────────────────────────────────────────
function hashPassword(password) {
    return crypto.createHash('sha256').update(password + 'user-apikey-salt').digest('hex');
}

function generateToken() {
    return 'uak_' + crypto.randomBytes(24).toString('hex');
}

function todayStr() {
    return new Date().toISOString().slice(0, 10);
}

function checkAndResetDaily(user) {
    const today = todayStr();
    if (user.lastResetDate !== today) {
        user.todayUsage = 0;
        user.lastResetDate = today;
        markDirty();
    }
    return user;
}

// ─── 用户 CRUD ────────────────────────────────────────────────

/**
 * 注册新用户
 */
export async function registerUser(username, password, inviteCode, configGetter) {
    ensureLoaded();

    // 检查邀请码（如果配置了）
    const config = configGetter ? configGetter() : {};
    if (config.inviteCode && config.inviteCode !== inviteCode) {
        return { success: false, reason: 'invalid_invite_code' };
    }

    if (userStore.users[username]) {
        return { success: false, reason: 'username_taken' };
    }

    if (!username || username.length < 2 || username.length > 32) {
        return { success: false, reason: 'invalid_username' };
    }

    if (!password || password.length < 6) {
        return { success: false, reason: 'password_too_short' };
    }

    const now = new Date().toISOString();
    userStore.users[username] = {
        username,
        passwordHash: hashPassword(password),
        role: 'user',           // 'user' | 'admin'
        apiKeys: {},             // { provider: apiKey } — 用户自己填的真实 API key
        dailyLimit: config.defaultDailyLimit ?? DEFAULT_DAILY_LIMIT,
        todayUsage: 0,
        totalUsage: 0,
        lastResetDate: todayStr(),
        lastUsedAt: null,
        enabled: true,
        createdAt: now,
    };
    markDirty();
    return { success: true };
}

/**
 * 用户登录，返回 token
 */
export async function loginUser(username, password) {
    ensureLoaded();
    const user = userStore.users[username];
    if (!user) return { success: false, reason: 'not_found' };
    if (!user.enabled) return { success: false, reason: 'disabled' };
    if (user.passwordHash !== hashPassword(password)) return { success: false, reason: 'wrong_password' };

    const token = generateToken();
    const expiryTime = Date.now() + 7 * 24 * 3600 * 1000; // 7天
    tokenStore.tokens[token] = { username, role: user.role, expiryTime };
    markDirty();
    return { success: true, token, role: user.role };
}

/**
 * 验证 token，返回用户信息
 */
export function verifyToken(token) {
    ensureLoaded();
    if (!token) return null;
    const info = tokenStore.tokens[token];
    if (!info) return null;
    if (Date.now() > info.expiryTime) {
        delete tokenStore.tokens[token];
        markDirty();
        return null;
    }
    const user = userStore.users[info.username];
    if (!user || !user.enabled) return null;
    return { username: info.username, role: user.role };
}

/**
 * 用户登出
 */
export async function logoutUser(token) {
    ensureLoaded();
    if (tokenStore.tokens[token]) {
        delete tokenStore.tokens[token];
        markDirty();
    }
}

/**
 * 获取用户信息（不含密码）
 */
export function getUser(username) {
    ensureLoaded();
    const user = userStore.users[username];
    if (!user) return null;
    const u = checkAndResetDaily({ ...user });
    const { passwordHash, ...safe } = u;
    return safe;
}

/**
 * 获取所有用户（管理员用）
 */
export function listUsers() {
    ensureLoaded();
    return Object.values(userStore.users).map(u => {
        const checked = checkAndResetDaily({ ...u });
        const { passwordHash, apiKeys, ...safe } = checked;
        return safe;
    });
}

/**
 * 更新用户的 API Key（用户自己保存自己的真实 key）
 */
export async function updateUserApiKey(username, provider, apiKey) {
    ensureLoaded();
    const user = userStore.users[username];
    if (!user) return { success: false, reason: 'not_found' };
    if (!user.apiKeys) user.apiKeys = {};
    user.apiKeys[provider] = apiKey;
    markDirty();
    return { success: true };
}

/**
 * 获取用户的 API Key（用于转发请求）
 */
export function getUserApiKey(username, provider) {
    ensureLoaded();
    const user = userStore.users[username];
    if (!user || !user.apiKeys) return null;
    return user.apiKeys[provider] || null;
}

/**
 * 获取用户所有 API Keys（脱敏，只显示前几位）
 */
export function getUserApiKeysMasked(username) {
    ensureLoaded();
    const user = userStore.users[username];
    if (!user || !user.apiKeys) return {};
    const masked = {};
    for (const [provider, key] of Object.entries(user.apiKeys)) {
        masked[provider] = key ? key.slice(0, 8) + '****' + key.slice(-4) : '';
    }
    return masked;
}

/**
 * 管理员更新用户属性（额度、启用状态、角色）
 */
export async function adminUpdateUser(username, updates) {
    ensureLoaded();
    const user = userStore.users[username];
    if (!user) return { success: false, reason: 'not_found' };

    if (updates.dailyLimit !== undefined) user.dailyLimit = Number(updates.dailyLimit);
    if (updates.enabled !== undefined) user.enabled = Boolean(updates.enabled);
    if (updates.role !== undefined && ['user', 'admin'].includes(updates.role)) user.role = updates.role;
    markDirty();
    return { success: true };
}

/**
 * 管理员重置用户今日用量
 */
export async function adminResetUsage(username) {
    ensureLoaded();
    const user = userStore.users[username];
    if (!user) return { success: false, reason: 'not_found' };
    user.todayUsage = 0;
    user.lastResetDate = todayStr();
    markDirty();
    return { success: true };
}

/**
 * 管理员删除用户
 */
export async function adminDeleteUser(username) {
    ensureLoaded();
    if (!userStore.users[username]) return { success: false, reason: 'not_found' };
    delete userStore.users[username];
    // 清理该用户的 token
    for (const [token, info] of Object.entries(tokenStore.tokens)) {
        if (info.username === username) delete tokenStore.tokens[token];
    }
    markDirty();
    return { success: true };
}

/**
 * 用户修改密码
 */
export async function changePassword(username, oldPassword, newPassword) {
    ensureLoaded();
    const user = userStore.users[username];
    if (!user) return { success: false, reason: 'not_found' };
    if (user.passwordHash !== hashPassword(oldPassword)) return { success: false, reason: 'wrong_password' };
    if (!newPassword || newPassword.length < 6) return { success: false, reason: 'password_too_short' };
    user.passwordHash = hashPassword(newPassword);
    markDirty();
    return { success: true };
}

/**
 * 记录一次请求使用
 * 返回 false 表示超过额度
 */
export function checkAndIncrementUsage(username) {
    ensureLoaded();
    const user = userStore.users[username];
    if (!user) return false;
    checkAndResetDaily(user);
    if (user.dailyLimit > 0 && user.todayUsage >= user.dailyLimit) {
        return false; // 超额
    }
    user.todayUsage++;
    user.totalUsage++;
    user.lastUsedAt = new Date().toISOString();
    markDirty();
    return true;
}

/**
 * 获取全局统计
 */
export function getGlobalStats() {
    ensureLoaded();
    const users = Object.values(userStore.users);
    return {
        totalUsers: users.length,
        activeUsers: users.filter(u => u.enabled).length,
        todayTotalUsage: users.reduce((s, u) => s + (u.todayUsage || 0), 0),
        totalUsage: users.reduce((s, u) => s + (u.totalUsage || 0), 0),
    };
}

/**
 * 清理过期 token
 */
export function cleanupExpiredTokens() {
    ensureLoaded();
    const now = Date.now();
    let changed = false;
    for (const [token, info] of Object.entries(tokenStore.tokens)) {
        if (now > info.expiryTime) {
            delete tokenStore.tokens[token];
            changed = true;
        }
    }
    if (changed) markDirty();
}

// 每5分钟清理过期 token
setInterval(cleanupExpiredTokens, 5 * 60 * 1000);
