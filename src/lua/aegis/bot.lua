-- AEGIS bot.lua — 恶意爬虫 / 扫描器 / 无头浏览器指纹拦截
local _M = {}
local common = require "aegis.common"

-- 高置信恶意 UA 关键词（命中直接拦截）
local EVIL_UA = {
    "sqlmap", "nikto", "nmap", "nessus", "acunetix", "burpsuite", "masscan",
    "hydra", "dirbuster", "wpscan", "gobuster", "ffuf", "whatweb", "openvas",
    "appscan", "zap", "arachni", "w3af", "havij", "metasploit", "netsparker",
    "joomscan", "cmseek", "nuclei", "xray", "byob", "spartan", "cobaltstrike",
    "mimikatz", "wscan", "bbscan", "dirmap", "fimap", "jaascois", "jbrofuzz",
    "xsstest", "xsser", "pangolin", "beef", "zmeu", "masscan", "zgrab"
}

-- 明显机器人/无头特征（不直接拦截，转给挑战页，真人浏览器可通过）
local SUSPECT_UA = {
    "python-requests", "python-urllib", "go-http-client", "libwww-perl",
    "scrapy", "mechanize", "okhttp", "java/", "curl/", "wget/", "httpie",
    "postmanruntime", "phantomjs", "headlesschrome", "python-httpx"
}

function _M.check(ip, dict)
    if common.conf("enable_bot_ua", true) ~= true then return "pass" end
    local ua = ngx.var.http_user_agent or ""
    ua = ua:lower()

    for _, k in ipairs(EVIL_UA) do
        if ua:find(k, 1, true) then
            common.log_attack("bot_ua", ip, "UA:" .. k, ngx.var.request_uri)
            common.ban_ip(dict, ip, 3600, "bot_ua")
            return "deny"
        end
    end
    for _, k in ipairs(SUSPECT_UA) do
        if ua:find(k, 1, true) then
            return "challenge"  -- 交给 JS 挑战判定（不直接封，避免误杀）
        end
    end
    return "pass"
end

return _M
