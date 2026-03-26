/**
 * 用户 API Key 插件 - 用户管理模块 v2
 * 新增：邀请码系统、注册开关、公告系统、首个用户自动成为 admin
 */

import { promises as fs } from 'fs';
import { existsSync, readFileSync, writeFileSync } from 'fs';
import path from 'path';
import crypto from 'crypto';
import logger from '../../utils/logger.js';

const USERS_STORE_FILE  = path.join(process.cwd(), 'configs', 'user-apikey-users.json');
const TOKEN_STORE_FILE  = path.join(process.cwd(), 'configs', 'user-apikey-tokens.json');
const SYSTEM_STORE_FILE = path.join(process.cwd(), 'configs', 'user-apikey-system.json');

const DEFAULT_DAILY_LIMIT = 200;

// ─── 内存缓存 ─────────────────────────────────────────────────
let userStore   = null; // { users: {} }
let tokenStore  = null; // { tokens: {} }
let systemStore = null; // { registerOpen, inviteCodes:{}, announcements:[] }
let isDirty     = false;
let persistTimer = null;

function ensureLoaded() {
    if (userStore !== null) return;

    userStore = load(USERS_STORE_FILE, { users: {} });
    tokenStore = load(TOKEN_STORE_FILE, { tokens: {} });
    systemStore = load(SYSTEM_STORE_FILE, {
        registerOpen: true,        // 是否允许注册
        requireInviteCode: false,  // 是否必须邀请码
        inviteCodes: {},           // { code: { note, usedBy, usedAt, usageLimit, usedCount, createdAt } }
        announcements: [],         // [{ id, content, createdAt, pinned }]
    });

    if (!persistTimer) {
        persistTimer = setInterval(persistIfDirty, 5000);
        process.on('beforeExit', persistSync);
        process.on('SIGINT',  () => { persistSync(); process.exit(0); });
        process.on('SIGTERM', () => { persistSync(); process.exit(0); });
    }
}

function load(file, defaultVal) {
    try {
        return existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : defaultVal;
    } catch(e) {
        logger.error('[UserApiKey] Failed to load', file, e.message);
        return defaultVal;
    }
}

async function persistIfDirty() {
    if (!isDirty) return;
    isDirty = false;
    try {
        await Promise.all([
            fs.writeFile(USERS_STORE_FILE,  JSON.stringify(userStore,   null, 2), 'utf8'),
            fs.writeFile(TOKEN_STORE_FILE,  JSON.stringify(tokenStore,  null, 2), 'utf8'),
            fs.writeFile(SYSTEM_STORE_FILE, JSON.stringify(systemStore, null, 2), 'utf8'),
        ]);
    } catch(e) { logger.error('[UserApiKey] Failed to persist:', e.message); }
}

function persistSync() {
    if (!isDirty) return;
    try {
        writeFileSync(USERS_STORE_FILE,  JSON.stringify(userStore,   null, 2), 'utf8');
        writeFileSync(TOKEN_STORE_FILE,  JSON.stringify(tokenStore,  null, 2), 'utf8');
        writeFileSync(SYSTEM_STORE_FILE, JSON.stringify(systemStore, null, 2), 'utf8');
    } catch(e) { /* ignore */ }
}

function markDirty() { isDirty = true; }

// ─── 工具 ─────────────────────────────────────────────────────
function hashPassword(p) {
    return crypto.createHash('sha256').update(p + 'user-apikey-salt').digest('hex');
}
function generateToken()     { return 'uak_'  + crypto.randomBytes(24).toString('hex'); }
function generateInviteCode() { return crypto.randomBytes(4).toString('hex').toUpperCase(); }
function nowISO()  { return new Date().toISOString(); }
function todayStr(){ return nowISO().slice(0, 10); }

function checkAndResetDaily(user) {
    if (user.lastResetDate !== todayStr()) {
        user.todayUsage = 0;
        user.lastResetDate = todayStr();
        markDirty();
    }
    return user;
}

function hasAnyAdmin() {
    return Object.values(userStore.users).some(u => u.role === 'admin');
}

// ─── 注册 & 登录 ───────────────────────────────────────────────

export async function registerUser(username, password, inviteCode) {
    ensureLoaded();

    // 注册开关（如果已有 admin，开关才生效；首个用户始终允许）
    const isFirst = Object.keys(userStore.users).length === 0;
    if (!isFirst && !systemStore.registerOpen) {
        return { success: false, reason: 'register_closed' };
    }

    // 邀请码验证（非首个用户 & 开启邀请码时校验）
    if (!isFirst && systemStore.requireInviteCode) {
        if (!inviteCode) return { success: false, reason: 'invite_required' };
        const code = systemStore.inviteCodes[inviteCode.toUpperCase()];
        if (!code) return { success: false, reason: 'invalid_invite_code' };
        const limit = code.usageLimit ?? 1;
        if (limit > 0 && (code.usedCount || 0) >= limit) {
            return { success: false, reason: 'invite_used_up' };
        }
    }

    if (userStore.users[username]) return { success: false, reason: 'username_taken' };
    if (!username || username.length < 2 || username.length > 32 || !/^[a-zA-Z0-9_\u4e00-\u9fa5]+$/.test(username)) {
        return { success: false, reason: 'invalid_username' };
    }
    if (!password || password.length < 6) return { success: false, reason: 'password_too_short' };

    const now = nowISO();
    // 首个用户自动成为 admin
    const role = isFirst ? 'admin' : 'user';

    userStore.users[username] = {
        username, passwordHash: hashPassword(password), role,
        apiKeys: {}, dailyLimit: DEFAULT_DAILY_LIMIT,
        todayUsage: 0, totalUsage: 0,
        lastResetDate: todayStr(), lastUsedAt: null,
        enabled: true, createdAt: now,
    };

    // 消耗邀请码
    if (!isFirst && systemStore.requireInviteCode && inviteCode) {
        const code = systemStore.inviteCodes[inviteCode.toUpperCase()];
        if (code) {
            code.usedCount = (code.usedCount || 0) + 1;
            if (!code.usedBy) code.usedBy = [];
            code.usedBy.push({ username, usedAt: now });
        }
    }

    markDirty();
    return { success: true, role };
}

export async function loginUser(username, password) {
    ensureLoaded();
    const user = userStore.users[username];
    if (!user) return { success: false, reason: 'not_found' };
    if (!user.enabled) return { success: false, reason: 'disabled' };
    if (user.passwordHash !== hashPassword(password)) return { success: false, reason: 'wrong_password' };

    const token = generateToken();
    tokenStore.tokens[token] = { username, role: user.role, expiryTime: Date.now() + 7*24*3600*1000 };
    markDirty();
    return { success: true, token, role: user.role };
}

export function verifyToken(token) {
    ensureLoaded();
    if (!token) return null;
    const info = tokenStore.tokens[token];
    if (!info) return null;
    if (Date.now() > info.expiryTime) { delete tokenStore.tokens[token]; markDirty(); return null; }
    const user = userStore.users[info.username];
    if (!user || !user.enabled) return null;
    return { username: info.username, role: user.role };
}

export async function logoutUser(token) {
    ensureLoaded();
    if (tokenStore.tokens[token]) { delete tokenStore.tokens[token]; markDirty(); }
}

// ─── 用户信息 ──────────────────────────────────────────────────

export function getUser(username) {
    ensureLoaded();
    const user = userStore.users[username];
    if (!user) return null;
    const u = checkAndResetDaily({ ...user });
    const { passwordHash, ...safe } = u;
    return safe;
}

export function listUsers() {
    ensureLoaded();
    return Object.values(userStore.users).map(u => {
        const checked = checkAndResetDaily({ ...u });
        const { passwordHash, apiKeys, ...safe } = checked;
        return safe;
    });
}

export async function updateUserApiKey(username, provider, apiKey) {
    ensureLoaded();
    const user = userStore.users[username];
    if (!user) return { success: false, reason: 'not_found' };
    if (!user.apiKeys) user.apiKeys = {};
    user.apiKeys[provider] = apiKey;
    markDirty();
    return { success: true };
}

export function getUserApiKey(username, provider) {
    ensureLoaded();
    const user = userStore.users[username];
    if (!user || !user.apiKeys) return null;
    return user.apiKeys[provider] || null;
}

export function getUserApiKeysMasked(username) {
    ensureLoaded();
    const user = userStore.users[username];
    if (!user || !user.apiKeys) return {};
    const masked = {};
    for (const [p, k] of Object.entries(user.apiKeys)) {
        masked[p] = k ? k.slice(0,8) + '****' + k.slice(-4) : '';
    }
    return masked;
}

export async function adminUpdateUser(username, updates) {
    ensureLoaded();
    const user = userStore.users[username];
    if (!user) return { success: false, reason: 'not_found' };
    if (updates.dailyLimit !== undefined) user.dailyLimit = Number(updates.dailyLimit);
    if (updates.enabled    !== undefined) user.enabled    = Boolean(updates.enabled);
    if (updates.role !== undefined && ['user','admin'].includes(updates.role)) {
        user.role = updates.role;
        // 同步失效该用户的 token（让其重新登录以获取新角色）
        for (const [t, info] of Object.entries(tokenStore.tokens)) {
            if (info.username === username) info.role = updates.role;
        }
    }
    markDirty();
    return { success: true };
}

export async function adminResetUsage(username) {
    ensureLoaded();
    const user = userStore.users[username];
    if (!user) return { success: false, reason: 'not_found' };
    user.todayUsage = 0; user.lastResetDate = todayStr();
    markDirty();
    return { success: true };
}

export async function adminDeleteUser(username) {
    ensureLoaded();
    if (!userStore.users[username]) return { success: false, reason: 'not_found' };
    delete userStore.users[username];
    for (const [t, info] of Object.entries(tokenStore.tokens)) {
        if (info.username === username) delete tokenStore.tokens[t];
    }
    markDirty();
    return { success: true };
}

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

export function checkAndIncrementUsage(username) {
    ensureLoaded();
    const user = userStore.users[username];
    if (!user) return false;
    checkAndResetDaily(user);
    if (user.dailyLimit > 0 && user.todayUsage >= user.dailyLimit) return false;
    user.todayUsage++; user.totalUsage++;
    user.lastUsedAt = nowISO();
    markDirty();
    return true;
}

export function getGlobalStats() {
    ensureLoaded();
    const users = Object.values(userStore.users);
    return {
        totalUsers:      users.length,
        activeUsers:     users.filter(u => u.enabled).length,
        todayTotalUsage: users.reduce((s,u) => s+(u.todayUsage||0), 0),
        totalUsage:      users.reduce((s,u) => s+(u.totalUsage||0), 0),
    };
}

// ─── 系统设置 ──────────────────────────────────────────────────

export function getSystemSettings() {
    ensureLoaded();
    return {
        registerOpen:      systemStore.registerOpen,
        requireInviteCode: systemStore.requireInviteCode,
    };
}

export async function updateSystemSettings(updates) {
    ensureLoaded();
    if (updates.registerOpen      !== undefined) systemStore.registerOpen      = Boolean(updates.registerOpen);
    if (updates.requireInviteCode !== undefined) systemStore.requireInviteCode = Boolean(updates.requireInviteCode);
    markDirty();
    return { success: true };
}

// ─── 邀请码 ────────────────────────────────────────────────────

export function listInviteCodes() {
    ensureLoaded();
    return Object.entries(systemStore.inviteCodes).map(([code, info]) => ({ code, ...info }));
}

export async function createInviteCode(note = '', usageLimit = 1) {
    ensureLoaded();
    const code = generateInviteCode();
    systemStore.inviteCodes[code] = {
        note, usageLimit: Number(usageLimit), usedCount: 0,
        usedBy: [], createdAt: nowISO(),
    };
    markDirty();
    return { success: true, code };
}

export async function deleteInviteCode(code) {
    ensureLoaded();
    if (!systemStore.inviteCodes[code.toUpperCase()]) return { success: false, reason: 'not_found' };
    delete systemStore.inviteCodes[code.toUpperCase()];
    markDirty();
    return { success: true };
}

// ─── 公告 ──────────────────────────────────────────────────────

export function listAnnouncements(activeOnly = false) {
    ensureLoaded();
    const all = systemStore.announcements || [];
    return activeOnly ? all.filter(a => !a.archived) : all;
}

export async function createAnnouncement(content, pinned = false) {
    ensureLoaded();
    if (!content || !content.trim()) return { success: false, reason: 'empty_content' };
    if (!systemStore.announcements) systemStore.announcements = [];
    const ann = {
        id: Date.now().toString(36) + crypto.randomBytes(2).toString('hex'),
        content: content.trim(),
        pinned: Boolean(pinned),
        archived: false,
        createdAt: nowISO(),
    };
    systemStore.announcements.unshift(ann);
    markDirty();
    return { success: true, announcement: ann };
}

export async function updateAnnouncement(id, updates) {
    ensureLoaded();
    const ann = (systemStore.announcements || []).find(a => a.id === id);
    if (!ann) return { success: false, reason: 'not_found' };
    if (updates.content  !== undefined) ann.content  = updates.content.trim();
    if (updates.pinned   !== undefined) ann.pinned   = Boolean(updates.pinned);
    if (updates.archived !== undefined) ann.archived = Boolean(updates.archived);
    markDirty();
    return { success: true };
}

export async function deleteAnnouncement(id) {
    ensureLoaded();
    const idx = (systemStore.announcements || []).findIndex(a => a.id === id);
    if (idx === -1) return { success: false, reason: 'not_found' };
    systemStore.announcements.splice(idx, 1);
    markDirty();
    return { success: true };
}

// ─── 清理 ──────────────────────────────────────────────────────

export function cleanupExpiredTokens() {
    ensureLoaded();
    const now = Date.now(); let changed = false;
    for (const [t, info] of Object.entries(tokenStore.tokens)) {
        if (now > info.expiryTime) { delete tokenStore.tokens[t]; changed = true; }
    }
    if (changed) markDirty();
}

setInterval(cleanupExpiredTokens, 5 * 60 * 1000);
