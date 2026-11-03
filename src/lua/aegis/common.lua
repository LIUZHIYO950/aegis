-- AEGIS common.lua — 公共工具
local _M = {}

local ngx = ngx
local re_find = ngx.re.find
local re_match = ngx.re.match
local cjson_ok, cjson = pcall(require, "cjson.safe")
if not cjson_ok then cjson_ok, cjson = pcall(require, "cjson") end
_M.json = cjson

-- 读取并解析配置文件（带缓存）
local config_cache = {}
function _M.load_config(path)
    local cached = config_cache[path]
    if cached and ngx.now() - cached.t < 10 then
        return cached.cfg
    end
    local f = io.open(path, "r")
    if not f then return {} end
    local content = f:read("*a")
    f:close()
    local cfg = {}
    for line in content:gmatch("[^\r\n]+") do
        line = line:gsub("#.*$", ""):gsub("%s+", " "):gsub("^%s+", ""):gsub("%s+$", "")
        if line ~= "" then
            local k, v = line:match("^(%S+)%s+(.-)$")
            if k then cfg[k] = v end
        end
    end
    config_cache[path] = { t = ngx.now(), cfg = cfg }
    return cfg
end

function _M.conf(key, default)
    local cfg = _M.load_config("/opt/aegis/conf/aegis.conf")
    local v = cfg[key]
    if v == nil or v == "" then return default end
    if v == "on" or v == "true" then return true end
    if v == "off" or v == "false" then return false end
    return v
end

-- 客户端 IP（支持 X-Forwarded-For 回源链）
function _M.client_ip()
    local ip = ngx.var.remote_addr
    local xff = ngx.var.http_x_forwarded_for
    if xff and xff ~= "" then
        local first = xff:match("([^,]+)")
        if first then ip = first:gsub("%s+", "") end
    end
    return ip
end

-- 是否为合法 IPv4
function _M.is_ipv4(ip)
    return ip and re_match(ip, [[^\d{1,3}(\.\d{1,3}){3}$]], "jo") ~= nil
end

-- 将 IP 放入共享内存封禁字典
function _M.ban_ip(dict, ip, sec, reason)
    if not _M.is_ipv4(ip) then return end
    local ok, err = dict:safe_add(ip, reason .. "|" .. os.time(), sec)
    if not ok and err ~= "exists" then
        dict:set(ip, reason .. "|" .. os.time(), sec)
    end
end

-- 校验 IP 是否命中 CIDR 黑名单
function _M.in_cidr(ip, cidr)
    if not cidr or cidr == "" then return false end
    local cip, bits = cidr:match("^([%d%.]+)/(%d+)$")
    if not bits then
        return ip == cidr
    end
    bits = tonumber(bits)
    local ip_a = _M.ip_to_num(ip)
    local c_a = _M.ip_to_num(cip)
    if not ip_a or not c_a then return false end
    local mask = bits == 0 and 0 or (0xffffffff << (32 - bits)) & 0xffffffff
    return (ip_a & mask) == (c_a & mask)
end

function _M.ip_to_num(ip)
    if not ip then return nil end
    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return nil end
    return tonumber(a) * 16777216 + tonumber(b) * 65536 + tonumber(c) * 256 + tonumber(d)
end

-- 写攻击日志（JSON 一行一条）
function _M.log_attack(attack_type, ip, rule_id, uri, extra)
    local rec = {
        time = ngx.time(),
        type = attack_type,
        ip = ip,
        rule = rule_id or "",
        uri = tostring(uri or ngx.var.uri):sub(1, 200),
        ua = tostring(ngx.var.http_user_agent or ""):sub(1, 100),
        extra = extra or ""
    }
    local ok, err = pcall(function()
        local f = io.open("/opt/aegis/logs/attack.log", "a")
        if f then f:write(_M.json.encode(rec) .. "\n"); f:close() end
    end)
    return ok ~= false
end

-- 按阶段检测请求各部分
function _M.uri_and_args()
    local parts = {}
    table.insert(parts, ngx.var.request_uri or "")
    local args = ngx.req.get_uri_args(0) or {}
    for k, v in pairs(args) do
        table.insert(parts, tostring(k))
        if type(v) == "table" then
            for _, vv in ipairs(v) do table.insert(parts, tostring(vv)) end
        else
            table.insert(parts, tostring(v))
        end
    end
    return table.concat(parts, " ")
end

return _M
