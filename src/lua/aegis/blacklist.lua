-- AEGIS blacklist.lua — 静态黑名单 + 动态封禁字典
local _M = {}
local common = require "aegis.common"

local dict_name = "aegis_blacklist"
local stat_file = "/opt/aegis/conf/blacklist.txt"

local static_ips = nil
local static_last_load = 0

-- 静态黑名单：读取文件，每 30 秒刷新一次
local function load_static()
    local now = os.time()
    if static_ips and now - static_last_load < 30 then
        return static_ips
    end
    local ips = {}
    local f = io.open(stat_file, "r")
    if f then
        for line in f:lines() do
            line = line:gsub("%s+", ""):gsub("#.*$", "")
            if line ~= "" then ips[line] = true end
        end
        f:close()
    end
    static_ips = ips
    static_last_load = now
    return ips
end

-- 白名单校验
function _M.is_whitelisted(ip)
    local wl = common.conf("whitelist_ips", "")
    if wl == "" then return false end
    for cidr in wl:gmatch("[^,]+") do
        cidr = cidr:gsub("%s+", "")
        if common.in_cidr(ip, cidr) then return true end
    end
    return false
end

-- 主检查：返回 reason 或 nil（放行）
function _M.check(ip, dict)
    if _M.is_whitelisted(ip) then return nil end
    if common.conf("enable_blacklist", true) ~= true then return nil end

    -- 动态封禁（秒级生效，含熔断/限流/WAF 触发的临时封禁）
    local dyn = dict and dict:get(ip)
    if dyn then return "dynamic:" .. dyn:match("^([^|]+)") end

    -- 静态黑名单
    for cidr, _ in pairs(load_static()) do
        if common.in_cidr(ip, cidr) then return "static:" .. cidr end
    end
    return nil
end

return _M
