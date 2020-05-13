
% TODO:
%
% - support for dynamic configuration sections, i.e. people naming system.web sweb
%   for this we need a prolog function to substitute values in a string, and a lookup
%   function for finding the configuration section name.
%
% Sources:
%
% - https://rehansaeed.com/securing-the-aspnet-mvc-web-config/
% - https://www.troyhunt.com/shhh-dont-let-your-response-headers/
% - https://www.itworld.com/article/2816097/top-application-security-vulnerabilities-in-web-config-files--part-1.html
% - https://www.itworld.com/article/2816071/top-application-security-vulnerabilities-in-web-config-files--part-2.html
% - https://gist.github.com/marcbarry/47644b4a43fbfb63ef54
% - https://docs.kentico.com/k10/securing-websites/deploying-websites-to-a-secure-environment/web-config-file-settings
% - https://docs.kentico.com/k10/securing-websites/security-checklists/security-checklist-deploying-a-website
% - https://support.secureauth.com/hc/en-us/articles/360019651392-How-To-Setup-HSTS-Response-Header-Via-Web-Config
% - https://www.saotn.org/enable-http-strict-transport-security-hsts-on-iis/
% - https://www.ryadel.com/en/iis-web-config-secure-http-response-headers-pass-securityheaders-io-scan/
% - https://support.microsoft.com/en-us/help/891028/asp-net-security-overview
% - https://blog.elmah.io/the-asp-net-core-security-headers-guide/
% - https://www.aligneddev.net/blog/2018/webconfig-aspnetmvc-security-and-perf/
% - https://lockmedown.com/owasp-5-security-misconfiguration-hardening-your-asp-net-app/
% - https://medium.com/bugbountywriteup/security-headers-1c770105940b
% - https://www.troyhunt.com/continuous-webconfig-security-analysis/

msg('no_auth', 'WARNING: No authentication specified.').
fnd('no_auth',[]) :- \+ xpath('/configuration/system.web/authentication',_).

msg('auth_mode', 'INFO: Authentication mode used: {0}.').
fnd('auth_mode', [Mode]) :- xpath('/configuration/system.web/authentication/@mode',Mode).

msg('auth_mode_none', 'WARNING: Authentication set to None.').
fnd('auth_mode_none', []) :- xpath('/configuration/system.web/authentication/@mode','None').

msg('auth_forms_credentials_present', 'ERROR: Forms authentication credentials stored in config file.').
fnd('auth_forms_credentials_present', []) :- xpath('/configuration/system.web/authentication/forms/credentials', _).

msg('auth_forms_credentials_format', 'INFO: Forms authentication credentials format: {0}.').
fnd('auth_forms_credentials_format', [Format]) :- xpath('/configuration/system.web/authentication/forms/credentials/@passwordFormat', Format).

msg('custom_errors', 'INFO: Custom errors mode: {0}.').
fnd('custom_errors', [Mode]) :- xpath('/configuration/system.web/customErrors/@mode', Mode).

msg('directory_browsing', 'ERROR: Directory browsing enabled.').
fnd('directory_browsing',[]) :- xpath('/configuration/system.webServer/directoryBrowse/@enabled', 'true').

msg('autz_mode', 'INFO: Authorizations specified.').
fnd('autz_mode', []) :- xpath('/configuration/system.web/authorization', _).

msg('cookies_not_http_only', 'ERROR: Cookie not HttpOnly.').
fnd('cookies_not_http_only', []) :- xpath('/configuration/system.web/httpCookies/@httpOnlyCookies', 'false').
% on .NET 4.0
fnd('cookies_not_http_only', []) :- \+ xpath('/configuration/system.web/httpCookies/@httpOnlyCookies', _).

msg('cookies_not_secure', 'ERROR: Cookie not Secure.').
fnd('cookies_not_secure', []) :- xpath('/configuration/system.web/httpCookies/@requireSSL', 'false').
% on .NET 4.0
fnd('cookies_not_secure', []) :- \+ xpath('/configuration/system.web/httpCookies/@requireSSL', _).

% https://docs.microsoft.com/en-us/previous-versions/dotnet/netframework-4.0/e1f13641(v=vs.100)
% https://gist.github.com/marcbarry/47644b4a43fbfb63ef54
% TODO: check if header removal in place
msg('http_header_version_info', 'ERROR: Server leaks version information through HTTP response.').
fnd('http_header_version_info', []) :- xpath('/configuration/system.web/httpRuntime/@enableVersionHeader', 'true').
fnd('http_header_version_info', []) :- \+ xpath('/configuration/system.web/httpRuntime/@enableVersionHeader', _).


msg('enable_http_header_checking_disabled', 'WARNING: HTTP header checking for injection attacks (httpRuntime/@enableHeaderChecking) disabled.').
fnd('enable_http_header_checking_disabled', []) :- xpath('/configuration/system.web/httpRuntime/@enableHeaderChecking', 'false').

msg('request_path_invalid_characters_changed', 'INFO: List of invalid characters in request path changed: {0}.').
fnd('request_path_invalid_characters_changed', [L]) :- xpath('/configuration/system.web/httpRuntime/@requestPathInvalidCharacters', L).

msg('cache_control_header_not_sent', 'WARNING: Cache-Control header not sent.').
fnd('cache_control_header_not_sent', []) :- xpath('/configuration/system.web/httpRuntime/@sendCacheControlHeader', 'false').


msg('tracing_enabled', 'ERROR: Tracing enabled.').
fnd('tracing_enabled', []) :- xpath('/configuration//trace/@enabled', 'true').

% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/security/requestfiltering/

msg('http_method_blacklist', 'WARNING: allowed/forbidden HTTP methods specified via negative validation (blacklist).').
fnd('http_method_blacklist', []) :- xpath('/configuration/system.webServer/security/requestFiltering/verbs/@allowUnlisted', 'true').
fnd('http_method_blacklist', []) :- \+ xpath('/configuration/system.webServer/security/requestFiltering/verbs/@allowUnlisted', _).

msg('trace_method_allowed', 'ERROR: TRACE method allowed.').
fnd('trace_method_allowed', []) :- xpath('/configuration/system.webServer/security/requestFiltering/verbs/add[@verb=\'TRACE\']/@allowed', 'true').
fnd('trace_method_allowed', []) :-
	fnd('http_method_blacklist', []),
	\+ xpath('/configuration/system.webServer/security/requestFiltering/verbs/add[@verb=\'TRACE\']/@allowed', _).

msg('http_method_allowed', 'INFO: HTTP {0} method allowed.').
fnd('http_method_allowed', [M]) :- xpath('/configuration/system.webServer/security/requestFiltering/verbs/add[@allowed=\'true\']/@verb', M).

msg('http_method_forbidden', 'INFO: HTTP {0} method forbidden.').
fnd('http_method_forbidden', [M]) :- xpath('/configuration/system.webServer/security/requestFiltering/verbs/add[@allowed=\'false\']/@verb', M).




finding(Message, L) :- msg(E,Message) , fnd(E,L).
q([M|L]) :- finding(M,L).



