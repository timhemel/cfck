
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

% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.compilationsection?view=netframework-4.8
compilation_version(V) :- xpath('/configuration/system.web/compilation/@targetFramework', V).
% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.httpruntimesection?view=netframework-4.8
runtime_version(V) :- xpath('/configuration/system.web/httpRuntime/@targetFramework', V).

msg('version_mismatch', 'WARNING: compilation and runtime targets not the same.').
fnd('version_mismatch', []) :- \+ ( compilation_version(V), runtime_version(V) ).

% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.compilationsection?view=netframework-4.8
msg('debug_enabled', 'ISSUE: Debug enabled.').
fnd('debug_enabled', []) :- xpath('/configuration/system.web/compilation/@debug', 'true').

% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.customerror?view=netframework-4.8
msg('custom_errors', 'INFO: Custom errors mode: {0}.').
fnd('custom_errors', [Mode]) :- xpath('/configuration/system.web/customErrors/@mode', Mode).

% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.authenticationsection?view=netframework-4.8
msg('no_auth', 'WARNING: No authentication specified.').
fnd('no_auth',[]) :- \+ xpath('/configuration/system.web/authentication',_).

msg('auth_mode', 'INFO: Authentication mode used: {0}.').
fnd('auth_mode', [Mode]) :- xpath('/configuration/system.web/authentication/@mode',Mode).

msg('auth_mode_none', 'WARNING: Authentication set to None.').
fnd('auth_mode_none', []) :- xpath('/configuration/system.web/authentication/@mode','None').

msg('auth_forms_credentials_present', 'ISSUE: Forms authentication credentials stored in config file.').
fnd('auth_forms_credentials_present', []) :- xpath('/configuration/system.web/authentication/forms/credentials', _).

msg('auth_forms_credentials_format', 'INFO: Forms authentication credentials format: {0}.').
fnd('auth_forms_credentials_format', [Format]) :- xpath('/configuration/system.web/authentication/forms/credentials/@passwordFormat', Format).

msg('auth_cookie_mode', 'INFO: Forms authentication cookie mode: {0}.').
fnd('auth_cookie_mode', [Mode]) :- xpath('/configuration/system.web/authentication/forms/@cookieless', Mode).

% TODO: check docs for true and false
msg('auth_cookieless_sessions', 'ISSUE: cookieless authentication allowed/possible.').
fnd('auth_cookieless_sessions', []) :- fnd('auth_cookie_mode', ['AutoDetect']).
fnd('auth_cookieless_sessions', []) :- fnd('auth_cookie_mode', ['UseUri']).
fnd('auth_cookieless_sessions', []) :- fnd('auth_cookie_mode', ['UseDeviceProfile']).
fnd('auth_cookieless_sessions', []) :- xpath('/configuration/system.web/authentication/forms',_), \+ fnd('auth_cookie_mode', _).

% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.authorizationsection?view=netframework-4.8
msg('autz_mode', 'INFO: Authorizations specified.').
fnd('autz_mode', []) :- xpath('/configuration/system.web/authorization', _).


% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.httpcookiessection?view=netframework-4.8
% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.httpcookiessection.httponlycookies?view=netframework-4.8#System_Web_Configuration_HttpCookiesSection_HttpOnlyCookies
msg('cookies_not_http_only', 'ISSUE: Cookie not HttpOnly.').
fnd('cookies_not_http_only', []) :- xpath('/configuration/system.web/httpCookies/@httpOnlyCookies', 'false').
% default is false
fnd('cookies_not_http_only', []) :- \+ xpath('/configuration/system.web/httpCookies/@httpOnlyCookies', _).

% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.httpcookiessection.requiressl?view=netframework-4.8#System_Web_Configuration_HttpCookiesSection_RequireSSL
msg('cookies_not_secure', 'ISSUE: Cookie not Secure.').
fnd('cookies_not_secure', []) :- xpath('/configuration/system.web/httpCookies/@requireSSL', 'false').
% default is false
fnd('cookies_not_secure', []) :- \+ xpath('/configuration/system.web/httpCookies/@requireSSL', _).

% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.httpcookiessection.samesite?view=netframework-4.8#System_Web_Configuration_HttpCookiesSection_SameSite
msg('cookies_not_samesite', 'ISSUE: Cookie not SameSite.').
% Values are Lax, None or Strict
fnd('cookies_not_samesite', []) :- xpath('/configuration/system.web/httpCookies/@sameSite', 'None').
% default is Lax on .NET 4.7.2 or later, None otherwise
fnd('cookies_not_samesite', []) :- runtime_version(V), \+ version_at_least('4.7.2',V), \+ xpath('/configuration/system.web/httpCookies/@sameSite', _).

% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.httpcookiessection.samesite?view=netframework-4.8#System_Web_Configuration_HttpCookiesSection_SameSite
msg('samesite_cookie_mode', 'INFO: cookie SameSite mode: {0}.').
% Values are Lax, None or Strict
% default is Lax on .NET 4.7.2 or later, None otherwise
fnd('samesite_cookie_mode', [Mode]) :- xpath('/configuration/system.web/httpCookies/@sameSite', Mode), !.
fnd('samesite_cookie_mode', ['Lax']) :- runtime_version(V), version_at_least('4.7.2',V), !.
fnd('samesite_cookie_mode', ['None']).


% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.httpmodulessection?view=netframework-4.8
% ???
msg('http_module_added', 'INFO: Extra HTTP module:    {0}: {1}.').
fnd('http_module_added', [Name, Type]) :- xpath('/configuration/system.web/httpModule/add', X), attr('name', Name), attr('type', Type).

% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.httpruntimesection?view=netframework-4.8

% TODO: Protect against ReDoS ?
% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.httpruntimesection.defaultregexmatchtimeout?view=netframework-4.8#System_Web_Configuration_HttpRuntimeSection_DefaultRegexMatchTimeout
% no default specified

% TODO: protect against header injection?
% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.httpruntimesection.enableheaderchecking?view=netframework-4.8#System_Web_Configuration_HttpRuntimeSection_EnableHeaderChecking
% default is true
msg('http_header_injection_protection_off', 'ISSUE: Server misses HTTP header injection protection.').
fnd('http_header_injection_protection_off', []) :- xpath('/configuration/system.web/httpRuntime/@enableHeaderChecking', 'false').

% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.httpruntimesection.enableversionheader?view=netframework-4.8#System_Web_Configuration_HttpRuntimeSection_EnableVersionHeader
% Unless the header is removed explicitly.
msg('http_header_asp_version_present', 'ISSUE: Server may leak version information through HTTP response.').
fnd('http_header_asp_version_present', []) :- xpath('/configuration/system.web/httpRuntime/@enableVersionHeader', 'true').
% default value is true
fnd('http_header_asp_version_present', []) :- \+ xpath('/configuration/system.web/httpRuntime/@enableVersionHeader', _).

% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.httpruntimesection.maxrequestlength?view=netframework-4.8#System_Web_Configuration_HttpRuntimeSection_MaxRequestLength
% default is 4096
msg('max_request_length_changed', 'INFO: Non-default value for maximum request length: {0}.').
fnd('max_request_length_changed', [L]) :- xpath('/configuration/system.web/httpRuntime/@maxRequestLength', L).

% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.httpruntimesection.requestpathinvalidcharacters?view=netframework-4.8#System_Web_Configuration_HttpRuntimeSection_RequestPathInvalidCharacters
msg('request_path_invalid_characters_changed', 'INFO: List of invalid characters in request path changed: {0}.').
fnd('request_path_invalid_characters_changed', [L]) :- xpath('/configuration/system.web/httpRuntime/@requestPathInvalidCharacters', L).

% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.httpruntimesection.requestvalidationmode?view=netframework-4.8#System_Web_Configuration_HttpRuntimeSection_RequestValidationMode
msg('request_validation_mode', 'INFO: Request validation mode (effective): {0}.').
fnd('request_validation_mode', ['0.0']) :-
	xpath('/configuration/system.web/httpRuntime/@requestValidationMode', '0.0'),
	runtime_version(V),
	version_at_least('4.6',V),
	!.
fnd('request_validation_mode', ['2.0']) :-
	xpath('/configuration/system.web/httpRuntime/@requestValidationMode', M),
	runtime_version(V),
	version_at_least('4.6',V),
	\+ version_at_least(M,'0.0'),
	\+ version_at_least('4.0',M),
	!.
fnd('request_validation_mode', ['2.0']) :-
	xpath('/configuration/system.web/httpRuntime/@requestValidationMode', M),
	runtime_version(V),
	version_at_least(V,'4.5'),
	\+ version_at_least('4.0',M),
	!.

fnd('request_validation_mode', ['4.5']) :-
	xpath('/configuration/system.web/httpRuntime/@requestValidationMode', M),
	runtime_version(V),
	version_at_least('4.6',V),
	version_at_least('4.5',M),
	!.
fnd('request_validation_mode', ['4.5']) :-
	xpath('/configuration/system.web/httpRuntime/@requestValidationMode', M),
	runtime_version(V),
	version_at_least(V,'4.5'),
	version_at_least('4.5',M),
	!.
fnd('request_validation_mode', [M]) :- xpath('/configuration/system.web/httpRuntime/@requestValidationMode', M), !.
% default is 4.5
fnd('request_validation_mode', ['4.5']).


% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.httpruntimesection.requestvalidationtype?view=netframework-4.8#System_Web_Configuration_HttpRuntimeSection_RequestValidationType
msg('request_validation_type', 'INFO: Custom request validation class: {0}.').
fnd('request_validation_type', [T]) :- xpath('/configuration/system.web/httpRuntime/@requestValidationType', T).

% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.httpruntimesection.sendcachecontrolheader?view=netframework-4.8#System_Web_Configuration_HttpRuntimeSection_SendCacheControlHeader
msg('cache_control_header_not_sent', 'WARNING: Cache-Control: private header not sent.').
fnd('cache_control_header_not_sent', []) :-
	runtime_version(V), version_at_least(V, '2.0'),
	xpath('/configuration/system.web/httpRuntime/@sendCacheControlHeader', 'false').
% default is false
fnd('cache_control_header_not_sent', []) :-
	runtime_version(V), version_at_least(V, '2.0'),
	\+ xpath('/configuration/system.web/httpRuntime/@sendCacheControlHeader', _).

% TODO: this needs more flexible matching
msg('anti_xss_encoder_not_used', 'WARNING: AntiXssEncoder not used.').
fnd('anti_xss_encoder_not_used', []) :- \+ xpath('/configuration/system.web/httpRuntime[contains(@encoderType,\'AntiXss\')]', _).

% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.machinekeysection?view=netframework-4.8
% TODO: check default settings
% TODO: check what other attributes mean
msg('crypto_algorithms_authsm_hash', 'INFO: Cryptographic hash algorithm for various authentication and session management functions: {0}.').
fnd('crypto_algorithms_authsm_hash', [X]) :- xpath('/configuration/system.web/machineKey/@validation', X).

% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.pagessection?view=netframework-4.8

% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.pagessection.enableeventvalidation?view=netframework-4.8#System_Web_Configuration_PagesSection_EnableEventValidation
% TODO: ?

% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.pagessection.enablesessionstate?view=netframework-4.8#System_Web_Configuration_PagesSection_EnableSessionState
% TODO: ?

% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.pagessection.enableviewstate?view=netframework-4.8#System_Web_Configuration_PagesSection_EnableViewState
% default is true.
msg('viewstate_disabled', 'INFO: viewstate disabled.').
fnd('viewstate_disabled', []) :- xpath('/configuration/system.web/pages/@enableViewState', 'false').

% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.pagessection.enableviewstatemac?view=netframework-4.8#System_Web_Configuration_PagesSection_EnableViewStateMac
% default is true.
%  should never be set to false in a production Web site, even if the application or page does not use view state.
%  The view state MAC helps ensure the security of other ASP.NET functions in addition to the view state.
msg('viewstatemac_disabled', 'INFO: viewstate MAC disabled.').
fnd('viewstatemac_disabled', []) :- xpath('/configuration/system.web/pages/@enableViewStateMac', 'false').

% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.pagessection.validaterequest?view=netframework-4.8#System_Web_Configuration_PagesSection_ValidateRequest
% default is true
msg('request_validation_disabled', 'ISSUE: Request validation disabled.').
fnd('request_validation_disabled', []) :- xpath('/configuration/system.web/pages/@validateRequest', 'false').

% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.pagessection.viewstateencryptionmode?view=netframework-4.8#System_Web_Configuration_PagesSection_ViewStateEncryptionMode
% default is Auto
msg('viewstate_encryption_mode', 'INFO: viewstate encryption mode: {0}.').
fnd('viewstate_encryption_mode', [M]) :- xpath('/configuration/system.web/pages/@viewStateEncryptionMode', M).

msg('viewstate_encryption_off', 'ISSUE: viewstate encryption disabled.').
fnd('viewstate_encryption_off', []) :- fnd('viewstate_encryption_mode', ['Never']).

% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.securitypolicysection?view=netframework-4.8
% TODO: ?

% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.sessionstatesection?view=netframework-4.8
% TODO: cookieless, cookieName, cookieSameSite
% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.sessionstatesection.cookieless?view=netframework-4.8#System_Web_Configuration_SessionStateSection_Cookieless
% default is false on asp.net < 2.0, Autodetect otherwise
msg('session_cookieless_mode', 'INFO: cookieless sessions mode: {0}.').
fnd('session_cookieless_mode', [M]) :- xpath('/configuration/system.web/sessionState/@cookieless', M), !.
fnd('session_cookieless_mode', ['AutoDetect']) :-
	\+ xpath('/configuration/system.web/sessionState/@cookieless', _),
	runtime_version(V), version_at_least('2.0',V), !.
fnd('session_cookieless_mode', ['false']) :-
	\+ xpath('/configuration/system.web/sessionState/@cookieless', _),
	runtime_version(V), \+ version_at_least('2.0',V).


msg('session_cookieless', 'ISSUE: cookieless sessions allowed/possible.').
fnd('session_cookieless', []) :- fnd('session_cookieless_mode', ['true']).
fnd('session_cookieless', []) :- fnd('session_cookieless_mode', ['AutoDetect']).
fnd('session_cookieless', []) :- fnd('session_cookieless_mode', ['UseUri']).
fnd('session_cookieless', []) :- fnd('session_cookieless_mode', ['UseDeviceProfile']).

% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.sessionstatesection.cookiename?view=netframework-4.8#System_Web_Configuration_SessionStateSection_CookieName
msg('session_cookie_name', 'INFO: non-default session cookie name: {0}.').
fnd('session_cookie_name', [M]) :- xpath('/configuration/system.web/sessionState/@cookieName', M).

% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.sessionstatesection.cookiesamesite?view=netframework-4.8#System_Web_Configuration_SessionStateSection_CookieSameSite
msg('session_cookie_samesite', 'INFO: session cookie SameSite mode: {0}.').
fnd('session_cookie_samesite', [M]) :- xpath('/configuration/system.web/sessionState/@cookieSameSite', M), !.
fnd('session_cookie_samesite', ['Lax']) :- runtime_version(V), version_at_least('4.7.2',V), !.
fnd('session_cookie_samesite', ['None']).

% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.sessionstatesection.regenerateexpiredsessionid?view=netframework-4.8#System_Web_Configuration_SessionStateSection_RegenerateExpiredSessionId
% default is true
%   By default, only cookieless URLs are reissued when RegenerateExpiredSessionId is enabled.
msg('session_regenerate_expired_sessionid', 'ISSUE: expired sessionid (in URL) not regenerated.').
fnd('session_regenerate_expired_sessionid', []) :- xpath('/configuration/system.web/sessionState/@regenerateExpiredSessionId', 'false').

% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.sessionstatesection.sqlconnectionstring?view=netframework-4.8#System_Web_Configuration_SessionStateSection_SqlConnectionString
% TODO: ?

% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.sessionstatesection.timeout?view=netframework-4.8#System_Web_Configuration_SessionStateSection_Timeout
% default: 20 minutes
msg('session_timeout', 'INFO: session timeout: {0} minutes.').
fnd('session_timeout', [X]) :- xpath('/configuration/system.web/sessionState/@timeout', X), !.
fnd('session_timeout', ['20']).

% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.sitemapsection?view=netframework-4.8
% TODO: ?


% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.tracesection?view=netframework-4.8
% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.tracesection.enabled?view=netframework-4.8#System_Web_Configuration_TraceSection_Enabled
% default is true
msg('tracing_enabled', 'INFO: Tracing enabled.').
fnd('tracing_enabled', []) :- xpath('/configuration/system.web/trace/@enabled', 'true').
fnd('tracing_enabled', []) :- \+ xpath('/configuration/system.web/trace/@enabled', _).

% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.tracesection.localonly?view=netframework-4.8#System_Web_Configuration_TraceSection_LocalOnly
% default is true
msg('tracing_enabled_local_only', 'ISSUE: Remote tracing enabled, but only local.').
fnd('tracing_enabled_local_only', []) :- xpath('/configuration/system.web/trace/@enabled', 'false').


% IIS
% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/


msg('directory_browsing', 'ISSUE: Directory browsing enabled.').
fnd('directory_browsing',[]) :- xpath('/configuration/system.webServer/directoryBrowse/@enabled', 'true').

% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/security/requestfiltering/
msg('http_method_blacklist', 'WARNING: allowed/forbidden HTTP methods specified via negative validation (blacklist).').
fnd('http_method_blacklist', []) :- xpath('/configuration/system.webServer/security/requestFiltering/verbs/@allowUnlisted', 'true').
fnd('http_method_blacklist', []) :- \+ xpath('/configuration/system.webServer/security/requestFiltering/verbs/@allowUnlisted', _).

msg('trace_method_allowed', 'ISSUE: TRACE method allowed.').
fnd('trace_method_allowed', []) :- xpath('/configuration/system.webServer/security/requestFiltering/verbs/add[@verb=\'TRACE\']/@allowed', 'true').
fnd('trace_method_allowed', []) :-
	fnd('http_method_blacklist', []),
	\+ xpath('/configuration/system.webServer/security/requestFiltering/verbs/add[@verb=\'TRACE\']/@allowed', _).

msg('http_method_allowed', 'INFO: HTTP {0} method allowed.').
fnd('http_method_allowed', [M]) :- xpath('/configuration/system.webServer/security/requestFiltering/verbs/add[@allowed=\'true\']/@verb', M).

msg('http_method_forbidden', 'INFO: HTTP {0} method forbidden.').
fnd('http_method_forbidden', [M]) :- xpath('/configuration/system.webServer/security/requestFiltering/verbs/add[@allowed=\'false\']/@verb', M).

msg('http_server_header_shown', 'ISSUE: IIS Server header shown.').
fnd('http_server_header_shown', []) :- \+ xpath('/configuration/system.webServer/security/requestFiltering[@removeServerHeader=\'true\']', _).

has_http_custom_header_with_value(H,V) :-
	xpath('/configuration/system.webServer/httpProtocol/customHeaders/add', X),
	attr(X, 'name', H), attr(X, 'value', V).

msg('http_custom_header', 'INFO: Custom HTTP header:    {0}: {1}').
fnd('http_custom_header', [H,V]) :- has_http_custom_header_with_value(H,V).

msg('missing_http_header', 'ISSUE: Missing HTTP header:    {0}').
missing_http_custom_header(X) :- \+ ( has_http_custom_header_with_value(H,_), lowercase(H,Y), lowercase(X,Y) ).
fnd('missing_http_header', ['X-Content-Type-Options']) :- missing_http_custom_header('X-Content-Type-Options').
fnd('missing_http_header', ['X-Frame-Options']) :- missing_http_custom_header('X-Frame-Options').
fnd('missing_http_header', ['X-XSS-Protection']) :- missing_http_custom_header('X-XSS-Protection').
fnd('missing_http_header', ['Content-Security-Policy']) :- missing_http_custom_header('Content-Security-Policy').
% TODO: referrer-policy
% TODO: x-permitted-cross-domain-policies
% TODO: expect-ct
% TODO: feature-policy
% TODO: strict-transport-security

http_header_removed(X) :- xpath('/configuration/system.webServer/httpProtocol/customHeaders/remove/@name', H), lowercase(H,Y), lowercase(X,Y).
% header removed with clear, unless redefined after the clear
http_header_removed(X) :-
	xpath('/configuration/system.webServer/httpProtocol/customHeaders/clear', _),
	\+ ( xpath('/configuration/system.webServer/httpProtocol/customHeaders/following-sibling::clear/add/@name', H),
	lowercase(H,Y), lowercase(X,Y) ).

msg('http_header_not_removed', 'ISSUE: HTTP header not removed:    {0}').
fnd('http_header_not_removed', ['X-Powered-By']) :- \+ http_header_removed('X-Powered-By').
% TODO: X-AspNetMvc-Version
% TODO: X-AspNet-Version    (also possible via other method)
% TODO: Server
% module: https://github.com/pingfu/iis-remove-server-headers

% system.webServer/httpErrors[@errorMode='Detailed']


% - glimpse[@defaultRuntimePolicy="Off"]
% - elmah
% - unencrypted db connectionstrings
% sessionState[@cookieless='false']
% pages enableViewStateMac=true etc.
% system.web/deployment[@retail='true']
% rename cookies: system.web/sessionState/@cookieName != 'ASP.NET_SessionId'
% configure custom error handlers
% remove unwanted modules: system.webServer/handlers/remove/@name (see https://gist.github.com/marcbarry/47644b4a43fbfb63ef54)

finding(Message, L) :- msg(E,Message) , fnd(E,L).
q([M|L]) :- finding(M,L).



