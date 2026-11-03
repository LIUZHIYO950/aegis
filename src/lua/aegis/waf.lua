-- AEGIS waf.lua — Web 攻击规则引擎 (SQLi/XSS/CMDi/路径遍历/XXE/SSRF/文件上传等)
local _M = {}
local common = require "aegis.common"

local rules = nil
local rules_last_load = 0
local RE_MAX = 64  -- 单条请求最多匹配规则数，防止正则爆炸

local function load_rules()
    local now = ngx.now()
    if rules and now - rules_last_load < 30 then return rules end
    local path = common.conf("waf_rules_file", "/opt/aegis/rules/waf-rules.json")
    local f = io.open(path, "r")
    if not f then return {} end
    local content = f:read("*a")
    f:close()
    local ok, data = pcall(common.json.decode, content)
    if not ok or not data or not data.rules then
        rules = {}
    else
        -- 预编译正则
        for _, r in ipairs(data.rules) do
            local pats = {}
            for _, p in ipairs(r.patterns or {}) do
                pats[#pats + 1] = { re = p, err = nil }
            end
            r._pats = pats
        end
        rules = data.rules
    end
    rules_last_load = now
    return rules
end

-- 检测主体：subject 为拼接后的文本（URI + args + headers + body 按需）
-- 返回命中的规则对象或 nil
function _M.scan(subject, ip, dict)
    if common.conf("enable_waf", true) ~= true then return nil end
    if #subject == 0 then return nil end

    local action = common.conf("waf_action", "deny")
    local block_sec = tonumber(common.conf("waf_block_sec", "3600")) or 3600
    local matched_count = 0

    for _, r in ipairs(load_rules()) do
        matched_count = matched_count + 1
        if matched_count > RE_MAX then break end
        local hit = false
        for _, p in ipairs(r._pats) do
            if common.re_find(subject, p.re, "jo") then
                hit = true
                break
            end
        end
        if hit then
            common.log_attack("waf", ip, tostring(r.id), ngx.var.request_uri,
                string.format("name=%s sev=%s", r.name, r.severity))
            if action == "deny" and (r.action == "deny" or r.action == nil) then
                common.ban_ip(dict, ip, block_sec, "waf:" .. r.id)
            end
            return r
        end
    end
    return nil
end

-- 请求体检测（POST/PUT，限制大小防 DoS）
function _M.scan_body(ip, dict)
    if common.conf("enable_body_check", true) ~= true then return nil end
    local ctype = ngx.var.content_type or ""
    if ctype:find("multipart", 1, true) then
        return nil  -- 文件上传的二进制内容交给上传规则在文件名层面拦截
    end
    local max = 64 * 1024  -- 只检查前 64KB，防内存耗尽
    ngx.req.read_body()
    local data = ngx.req.get_body_data()
    if not data then return nil end
    if #data > max then data = data:sub(1, max) end
    return _M.scan(data, ip, dict)
end

return _M
