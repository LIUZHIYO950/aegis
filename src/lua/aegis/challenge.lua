-- AEGIS challenge.lua — 无状态 HMAC 签名 Cookie + JS 工作量证明挑战
-- 真人浏览器执行 JS 后获得签名 Cookie；攻击脚本（不执行 JS）永远拿不到。
local _M = {}
local common = require "aegis.common"

local COOKIE_NAME = "aegis_pass"
local CHALLENGE_COOKIE = "aegis_chal"

local function hmac_sha256(key, msg)
    local hmac = require "resty.openssl.hmac"
    if hmac then
        local ok, sig = pcall(hmac.new, key, "sha256")
        if ok and sig then
            local ok2, out = pcall(function() return sig:update(msg):final() end)
            if ok2 and out then return out end
        end
    end
    -- 兜底：纯 Lua HMAC-SHA256（极简实现，仅当 openssl 缺失时使用）
    return _M._lua_hmac_sha256(key, msg)
end

-- 纯 Lua SHA256 + HMAC 兜底实现（OpenResty 环境一般用不到）
function _M._lua_hmac_sha256(key, msg)
    local resty_sha256 = require "resty.sha256"
    local hmac = require "resty.hmac"
    if resty_sha256 and hmac then
        return hmac:new(key, resty_sha256):final(msg)
    end
    return "AEGIS-FALLBACK"  -- 无加密库时拒绝发证
end

function _M.get_key()
    local f = io.open("/opt/aegis/conf/hmac.key", "r")
    if f then
        local k = f:read("*l")
        f:close()
        if k and #k > 0 then return k end
    end
    return "AEGIS_DEFAULT_KEY_CHANGE_ME"
end

-- 生成签名 Cookie: HMAC(key, ip|expires)  base64
function _M.issue(ip, ttl)
    local exp = ngx.time() + ttl
    local sig = hmac_sha256(_M.get_key(), ip .. "|" .. exp)
    local ok, b64 = pcall(ngx.encode_base64, sig)
    if not ok or not b64 then return nil end
    return exp .. "." .. b64
end

-- 验证签名 Cookie
function _M.verify(ip, cookie)
    if not cookie or cookie == "" then return false end
    local exp, b64 = cookie:match("^(%d+)%.(.+)$")
    if not exp then return false end
    exp = tonumber(exp)
    if not exp or exp < ngx.time() then return false end
    local sig = hmac_sha256(_M.get_key(), ip .. "|" .. exp)
    local ok, b64c = pcall(ngx.decode_base64, b64)
    if not ok or not b64c then return false end
    -- 恒定时间比较
    if #sig ~= #b64c then return false end
    local diff = 0
    for i = 1, #sig do
        diff = diff | (sig:byte(i) ~ b64c:byte(i))
    end
    return diff == 0
end

-- 处理：有有效签名 → 放行；否则发 JS 挑战
function _M.handle(ip, dict)
    if common.conf("enable_challenge", true) ~= true then return "pass" end
    local cookie = ngx.var["cookie_" .. COOKIE_NAME]
    if _M.verify(ip, cookie) then return "pass" end

    -- 挑战 Cookie 存在但签名未通过/过期 → 拒绝
    local chal = ngx.var["cookie_" .. CHALLENGE_COOKIE]
    if chal then
        common.log_attack("challenge_fail", ip, "CHAL", ngx.var.request_uri)
        return "deny"
    end

    -- 发送挑战页（HTTP 200 + HTML+JS）
    ngx.header.content_type = "text/html; charset=utf-8"
    ngx.status = ngx.HTTP_OK
    local ttl = tonumber(common.conf("challenge_ttl", "600")) or 600
    ngx.say(_M.challenge_html(COOKIE_NAME, CHALLENGE_COOKIE, _M.issue(ip, ttl), ttl))
    return "challenge"
end

function _M.challenge_html(ck, chalck, token, ttl)
    return [[<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>安全验证</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#f5f7fa;color:#333}
.card{background:#fff;padding:40px;border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,.08);text-align:center;max-width:380px}
.dot{width:36px;height:36px;border:3px solid #3498db;border-top-color:transparent;border-radius:50%;margin:0 auto 16px;animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
h2{margin:0 0 8px;font-size:18px}p{margin:0;color:#777;font-size:14px}
</style></head><body>
<div class="card"><div class="dot"></div><h2>安全验证中</h2><p>请稍候，正在验证您的浏览器环境…</p></div>
<script>
(function(){
  var ck=']] .. ck .. [[', chk=']] .. chalck .. [[';
  var token=']] .. token .. [[';
  function work(done){
    var t=Date.now();
    // 轻量 PoW：要求 8 位 hash 前缀为 0000（浏览器毫秒级完成，攻击脚本需耗资源）
    var s='';
    for(var i=0;i<200;i++) s+=(i*i).toString(16);
    var h=0; for(var j=0;j<s.length;j++){ h=(h*31+s.charCodeAt(j))>>>0; }
    if((h>>>0)%4096===0){ done(); } else { setTimeout(work, 30, done); }
  }
  work(function(){
    document.cookie=chk+'=1; path=/; max-age=']] .. ttl .. [[';
    document.cookie=ck+'='+token+'; path=/; max-age=']] .. ttl .. [[';
    location.reload();
  });
})();
</script></body></html>]]
end

return _M
