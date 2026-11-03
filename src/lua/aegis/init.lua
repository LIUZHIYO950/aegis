-- ============================================================
-- AEGIS init.lua — 请求级防护主入口 (access 阶段)
-- 执行顺序: 黑名单 → 恶意UA → WAF → 限流 → 熔断 → JS挑战 → body检测
-- ============================================================
local common    = require "aegis.common"
local blacklist = require "aegis.blacklist"
local waf       = require "aegis.waf"
local bot       = require "aegis.bot"
local ratelimit = require "aegis.ratelimit"
local flow      = require "aegis.flow"
local challenge = require "aegis.challenge"

local dict = ngx.shared.aegis_blacklist
local ip = common.client_ip()

local function deny_page(title, msg, retry)
    ngx.header.content_type = "text/html; charset=utf-8"
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.say([[<!DOCTYPE html><html><head><meta charset="utf-8"><title>]] .. title ..
        [[</title><style>body{font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#f5f7fa;color:#333}.card{background:#fff;padding:40px;border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,.08);text-align:center;max-width:400px}.code{font-size:42px;font-weight:bold;color:#e74c3c}div{margin:8px 0;color:#777;font-size:14px}</style></head><body>
<div class="card"><div class="code">]] .. title .. [[</div><div>]] .. msg .. [[</div>
]] .. (retry and "<div>请检查后重试。</div>" or "") .. [[</div></body></html>]])
    return ngx.exit(ngx.HTTP_FORBIDDEN)
end

local function busy_page()
    ngx.header.content_type = "text/html; charset=utf-8"
    ngx.status = ngx.HTTP_SERVICE_UNAVAILABLE
    ngx.say([[<!DOCTYPE html><html><head><meta charset="utf-8"><title>服务器繁忙</title><style>body{font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#f5f7fa;color:#333}.card{background:#fff;padding:40px;border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,.08);text-align:center}.t{font-size:40px;font-weight:bold;color:#f39c12}.d{margin-top:10px;color:#777}</style></head><body><div class="card"><div class="t">服务器繁忙</div><div class="d">当前访问量过大，请稍后再试。</div></div></body></html>]])
    return ngx.exit(ngx.HTTP_SERVICE_UNAVAILABLE)
end

-- 0) 基础检查（IP 有效性）
if not ip or ip == "" then
    return ngx.exit(ngx.HTTP_BAD_REQUEST)
end

-- 0.5) 蜜罐路径（可选：诱捕后台扫描者；命中即记录并返回 403）
local honeypot_paths = common.conf("honeypot_paths", "") or ""
if honeypot_paths ~= "" then
    local uri = ngx.var.request_uri or ""
    for p in string.gmatch(honeypot_paths, "[^,]+") do
        p = p:gsub("^%s+", ""):gsub("%s+$", "")
        if p ~= "" and uri:find(p, 1, true) == 1 then
            common.log_attack("honeypot", ip, "HONEY", uri, "honeypot hit")
            return deny_page("403", "访问已记录并拦截。")
        end
    end
end

-- 1) 黑名单
local ban = blacklist.check(ip, dict)
if ban then
    common.log_attack("blacklist", ip, ban, ngx.var.request_uri)
    return deny_page("403", "您的访问已被防火墙拦截。")
end

-- 2) 恶意 UA
local bot_result = bot.check(ip, dict)
if bot_result == "deny" then
    return deny_page("403", "检测到恶意扫描行为，访问已拦截。")
end

-- 3) WAF: URI + 参数
local waf_hit = waf.scan(common.uri_and_args(), ip, dict)
if waf_hit then
    return deny_page("403", "请求包含恶意载荷，已拦截。")
end

-- 4) 单 IP 限流
if ratelimit.check(ip, dict) then
    return deny_page("403", "访问过于频繁，请稍后再试。")
end

-- 5) 签名 Cookie 状态
local has_pass = challenge.verify(ip, ngx.var["cookie_aegis_pass"])

-- 6) 全局熔断（只针对无签名流量；熔断冷却期内新请求直接 503）
if not has_pass then
    if flow.is_breaking(dict) then
        return busy_page()
    end
    if flow.check(ip, dict) then
        return busy_page()
    end
end

-- 7) JS 挑战（无签名 → 发挑战页）
if not has_pass then
    local r = challenge.handle(ip, dict)
    if r == "deny" then
        return deny_page("403", "安全验证失败，访问已拦截。")
    end
    if r == "challenge" then
        return ngx.exit(ngx.HTTP_OK)  -- 挑战页已输出
    end
    has_pass = true
end

-- 8) 请求体检测（POST/PUT，且持证流量同样检测防攻击者）
if ngx.req.get_method() == "POST" or ngx.req.get_method() == "PUT" then
    local body_hit = waf.scan_body(ip, dict)
    if body_hit then
        return deny_page("403", "请求包含恶意载荷，已拦截。")
    end
end

-- 放行
