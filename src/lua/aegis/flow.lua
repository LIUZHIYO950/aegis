-- AEGIS flow.lua — 全局熔断器 (CC / HTTP Flood)
-- 针对"无签名 Cookie"流量：达到阈值即全局限流（30 秒冷却），
-- 保护后端不被瞬时洪峰打垮；持证正常用户不受影响。
local _M = {}
local common = require "aegis.common"

local dict_name = "aegis_flow"

function _M.check(ip, dict)
    if common.conf("enable_flow_breaker", true) ~= true then return false end

    local windows = {
        { sec = 1,  max = tonumber(common.conf("breaker_t1_reqs", "300")) or 300 },
        { sec = 3,  max = tonumber(common.conf("breaker_t2_reqs", "500")) or 500 },
        { sec = 10, max = tonumber(common.conf("breaker_t3_reqs", "1200")) or 1200 },
    }
    local cooldown = tonumber(common.conf("breaker_cooldown_sec", "30")) or 30

    local triggered = false
    for _, w in ipairs(windows) do
        local bucket = math.floor(ngx.now() / w.sec)
        local key = "G:" .. bucket .. ":" .. w.sec
        local cnt = dict:incr(key, 1, 0)
        if not cnt then goto continue end
        if cnt == 1 then dict:expire(key, w.sec * 2 + 5) end
        if cnt > w.max then triggered = true end
        ::continue::
    end

    if triggered then
        -- 熔断标记：30 秒内新请求直接 503
        dict:set("breaker:on", ngx.now(), cooldown)
        common.log_attack("flow_breaker", ip, "FLOW", ngx.var.request_uri,
            string.format("window=%ds cooldown=%ds", 1, cooldown))
        return true
    end

    -- UA 聚合熔断（分布式 CC：大量不同 IP 但 UA 相同的无签名流量）
    if common.conf("enable_ua_flow", true) ~= false then
        local ua = string.sub(ngx.var.http_user_agent or "unknown", 1, 96)
        local ua_bucket = math.floor(ngx.now() / 5)
        local ua_key = "UA:" .. ua .. ":" .. ua_bucket
        local ua_cnt = dict:incr(ua_key, 1, 0)
        if ua_cnt and ua_cnt == 1 then dict:expire(ua_key, 15) end
        local ua_max = tonumber(common.conf("ua_flow_max", "200")) or 200
        if ua_cnt and ua_cnt > ua_max and ua ~= "unknown" then
            dict:set("breaker:on", ngx.now(), cooldown)
            common.log_attack("ua_flow", ip, "UA-FLOW", ngx.var.request_uri,
                string.format("ua=%s cnt=%d", ua, ua_cnt))
            return true
        end
    end
    -- 熔断状态检查（由 init 调用）
    if dict:get("breaker:on") then return true end
    return false
end

-- 单独判断当前是否处于熔断冷却期（避免重复触发计数）
function _M.is_breaking(dict)
    return dict:get("breaker:on") ~= nil
end

return _M
