-- AEGIS ratelimit.lua — 单 IP 滑动窗口限流
local _M = {}
local common = require "aegis.common"

local dict_name = "aegis_rate"

-- 基于 lua_shared_dict 的固定窗口计数（窗口 5s，足够精细且开销极小）
function _M.check(ip, dict)
    if common.conf("enable_rate_limit", true) ~= true then return false end

    -- 登录/认证接口走独立更严限流（撞库/爆破防护）
    local login_paths = common.conf("login_paths", "") or ""
    local uri = ngx.var.request_uri or ""
    local is_login = false
    for p in string.gmatch(login_paths, "[^,]+") do
        p = p:gsub("^%s+", ""):gsub("%s+$", "")
        if p ~= "" and uri:find(p, 1, true) == 1 then
            is_login = true
            break
        end
    end
    local win, max, ban_sec
    if is_login then
        win     = tonumber(common.conf("login_window_sec", "60")) or 60
        max     = tonumber(common.conf("login_max_reqs", "10")) or 10
        ban_sec = tonumber(common.conf("login_ban_sec", "1800")) or 1800
    else
        win     = tonumber(common.conf("rate_window_sec", "5")) or 5
        max     = tonumber(common.conf("rate_max_reqs", "80")) or 80
        ban_sec = tonumber(common.conf("rate_ban_sec", "120")) or 120
    end

    local bucket = math.floor(ngx.now() / win)
    local key = ip .. ":" .. bucket
    local cnt, err = dict:incr(key, 1, 0)
    if not cnt then return false end
    if cnt == 1 then
        -- 下个窗口自动过期；同时给上个窗口续命防止抖动
        dict:expire(key, win * 2 + 5)
    end
    if cnt > max then
        common.ban_ip(dict, ip, ban_sec, "ratelimit")
        common.log_attack("rate_limit", ip, "RATE", ngx.var.request_uri,
            string.format("cnt=%d max=%d", cnt, max))
        return true
    end
    return false
end

return _M
