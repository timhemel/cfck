
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

system_web(W,'/') :- xpath('/configuration/system.web', W).
system_web(W,Path) :- xpath('/configuration/location/system.web', W), relxpath(W, 'ancestor::location/@path', Path).


% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.compilationsection?view=netframework-4.8
compilation_version(V) :- xpath('/configuration/system.web/compilation/@targetFramework', V).
% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.httpruntimesection?view=netframework-4.8
runtime_version(V) :- xpath('/configuration/system.web/httpRuntime/@targetFramework', V).

msg('compilation_version', 'INFO: compilation target version: {0}.').
fnd('compilation_version', [V]) :- compilation_version(V).
msg('runtime_version', 'INFO: runtime target version: {0}.').
fnd('runtime_version', [V]) :- runtime_version(V).

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

msg('auth_forms_require_ssl', 'ISSUE: Forms authentication does not require SSL.').
fnd('auth_forms_require_ssl', []) :- xpath('/configuration/system.web/authentication/forms/@requireSSL', 'false').

msg('auth_forms_cookie_name', 'INFO: Forms authentication cookie name: {0}.').
fnd('auth_forms_cookie_name', [Name]) :- xpath('/configuration/system.web/authentication/forms/@name', Name).

msg('auth_forms_login_url', 'INFO: Forms authentication login URL: {0}.').
fnd('auth_forms_login_url', [Url]) :- xpath('/configuration/system.web/authentication/forms/@loginUrl', Url).

% TODO: check docs for true and false
msg('auth_cookieless_sessions', 'ISSUE: cookieless authentication allowed/possible.').
fnd('auth_cookieless_sessions', []) :- fnd('auth_cookie_mode', ['AutoDetect']).
fnd('auth_cookieless_sessions', []) :- fnd('auth_cookie_mode', ['UseUri']).
fnd('auth_cookieless_sessions', []) :- fnd('auth_cookie_mode', ['UseDeviceProfile']).
fnd('auth_cookieless_sessions', []) :- xpath('/configuration/system.web/authentication/forms',_), \+ fnd('auth_cookie_mode', _).

% https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.authorizationsection?view=netframework-4.8
msg('autz_mode', 'DEBUG: INFO: authorizations specified for path {0}.').
fnd('autz_mode', [Path]) :- system_web(W,Path), relxpath(W, 'authorization', _).



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
fnd('http_module_added', [Name, Type]) :- xpath('/configuration/system.web/httpModule/add', X), attr(X, 'name', Name), attr(X, 'type', Type).

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
fnd('session_timeout', ['20 (default)']).

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

% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/asp/

% client-side debugging, default is false
msg('client_side_debugging_enabled', 'ISSUE: Client-side debugging enabled.').
fnd('client_side_debugging_enabled', []) :-
	xpath('/configuration/system.webServer/asp/@appAllowClientDebug', 'true').
% server-side debugging, default is false
msg('server_side_debugging_enabled', 'ISSUE: Server-side debugging enabled.').
fnd('server_side_debugging_enabled', []) :-
	xpath('/configuration/system.webServer/asp/@appAllowDebugging', 'true').

% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/asp/session
% keepSessionIdSecure: default true
msg('asp_keep_session_id_secure', 'ISSUE: ASP session ID not a secure cookie.').
fnd('asp_keep_session_id_secure', []) :-
	xpath('/configuration/system.webServer/asp/session/@keepSessionIdSecure', 'false').
% max concurrent sessions
msg('asp_max_concurrent_sessions', 'INFO: ASP max concurrent sessions limited to {0}.').
fnd('asp_max_concurrent_sessions', [N]) :-
	xpath('/configuration/system.webServer/asp/session/@max', N).
% timeout, default 20 min
msg('asp_session_timeout', 'INFO: ASP session timeout: {0}.').
fnd('asp_session_timeout', [N]) :-
	xpath('/configuration/system.webServer/asp/session/@timeout', N).

% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/directorybrowse
msg('directory_browsing', 'ISSUE: Directory browsing enabled.').
fnd('directory_browsing',[]) :- xpath('/configuration/system.webServer/directoryBrowse/@enabled', 'true').

% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/globalmodules/
% TODO: check for clear and remove
msg('iis_module_installed', 'INFO: IIS module installed: {0} from {1}.').
fnd('iis_module_installed',[M,P]) :- xpath('/configuration/system.webServer/globalModules/add', X), attr(X, 'name',M), attr(X, 'image',P).

% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/handlers/
% TODO: check for clear and remove
msg('iis_handler_enabled', 'INFO: IIS handler enabled: {0} for {1}.').
fnd('iis_handler_enabled',[M,P]) :- xpath('/configuration/system.webServer/handlers/add', X), attr(X, 'name',M), attr(X, 'path',P).

% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/httpcompression/
% TODO: has some settings related to caching and compressed files: cacheControlHeader, expiresHeader, sendCacheHeaders


% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/httperrors/
% default is DetailedLocalOnly
msg('iis_detailed_error_message', 'ISSUE: IIS gives detailed error messages.').
fnd('iis_detailed_error_message',[]) :- xpath('/configuration/system.webServer/httpErrors/@errorMode', 'Detailed').

% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/httplogging
% TODO: selectiveLogging, default is LogAll, dontLog, default is false

% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/httpprotocol/

% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/httpprotocol/customheaders/
% TODO: should perhaps check for clear and remove, but who would add and then remove a header?
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

msg('http_header_not_removed', 'ISSUE: HTTP header (possibly) not removed:    {0}').
fnd('http_header_not_removed', ['X-Powered-By']) :- \+ http_header_removed('X-Powered-By').
fnd('http_header_not_removed', ['X-AspNetMvc-Version']) :- \+ http_header_removed('X-AspNetMvc-Version').
fnd('http_header_not_removed', ['X-AspNet-Version']) :- \+ http_header_removed('X-AspNet-Version').
fnd('http_header_not_removed', ['Server']) :- \+ http_header_removed('Server').
% TODO: X-AspNetMvc-Version
% TODO: X-AspNet-Version    (also possible via other method)
% TODO: Server
% module: https://github.com/pingfu/iis-remove-server-headers

% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/httpprotocol/redirectheaders/
msg('http_extra_redirect_header', 'INFO: HTTP extra redirect header:    {0}: {1}').
fnd('http_extra_redirect_header', [H,V]) :-
	xpath('/configuration/system.webServer/httpProtocol/redirectHeaders/add', X),
	attr(X, 'name', H), attr(X, 'value', V).

% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/isapifilters/
msg('iis_isapi_filter_enabled', 'INFO: IIS ISAPI filter {0} for {1}, enabled={2}.').
fnd('iis_isapi_filter_enabled',[M,P,E]) :-
	xpath('/configuration/system.webServer/isapiFilters/filter', X),
	attr(X, 'name',M), attr(X, 'path',P), optional_attr(X, 'enabled',E,'true').

% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/management/
% TODO: authentication, authorization, trustedProviders...

% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/modules/
% TODO: ?

% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/odbclogging
% TODO: hardcoded passwords?

% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/security/

% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/security/access
% sslFlags: default is None
msg('iis_ssl_disabled', 'ISSUE: IIS disables SSL.').
fnd('iis_ssl_disabled', []) :- xpath('/configuration/system.webServer/security/access[contains(@sslFlags, \'None\')]', _), !.
fnd('iis_ssl_disabled', []) :- \+ xpath('/configuration/system.webServer/security/access/@sslFlags', _).

msg('iis_clientcert_optional', 'ISSUE: IIS client certificates are optional.').
fnd('iis_clientcert_optional', []) :- xpath('/configuration/system.webServer/security/access[contains(@sslFlags, \'SslNegotiateCert\')]', _).

msg('iis_ssl_128_bit', 'WARNING: IIS uses 128 bit SSL.').
fnd('iis_ssl_128_bit', []) :- xpath('/configuration/system.webServer/security/access[contains(@sslFlags, \'Ssl128\')]', _).

% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/security/applicationdependencies/
% TODO: ?

% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/security/authentication/
% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/security/authentication/anonymousauthentication
msg('iis_anonymous_authentication', 'INFO: IIS explicit setting: anonymous authentication = {0}.').
fnd('iis_anonymous_authentication', [E]) :- xpath('/configuration/system.webServer/security/authentication/anonymousAuthentication/@enabled', E).
% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/security/authentication/basicauthentication
msg('iis_basic_authentication', 'INFO: IIS explicit setting: basic authentication = {0}.').
fnd('iis_basic_authentication', [E]) :- xpath('/configuration/system.webServer/security/authentication/basicAuthentication/@enabled', E).
% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/security/authentication/clientcertificatemappingauthentication
msg('iis_clientcert_mapping_authentication', 'INFO: IIS explicit setting: AD clientcert mapping authentication = {0}.').
fnd('iis_clientcert_mapping_authentication', [E]) :- xpath('/configuration/system.webServer/security/authentication/clientCertificateMappingAuthentication/@enabled', E).
% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/security/authentication/digestauthentication
msg('iis_digest_authentication', 'INFO: IIS explicit setting: digest authentication = {0}.').
fnd('iis_digest_authentication', [E]) :- xpath('/configuration/system.webServer/security/authentication/digestAuthentication/@enabled', E).
% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/security/authentication/iisclientcertificatemappingauthentication/
msg('iis_iis_clientcert_mapping_authentication', 'INFO: IIS explicit setting: IIS clientcert mapping authentication = {0}.').
fnd('iis_iis_clientcert_mapping_authentication', [E]) :- xpath('/configuration/system.webServer/security/authentication/iisClientCertificateMappingAuthentication/@enabled', E).
% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/security/authentication/windowsauthentication/
msg('iis_windows_authentication', 'INFO: IIS explicit setting: Windows (NTLM) authentication = {0}.').
fnd('iis_windows_authentication', [E]) :- xpath('/configuration/system.webServer/security/authentication/digestAuthentication/@enabled', E).

% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/security/authorization/
% TODO: this is something to check on itself
msg('iis_authorization', 'INFO: IIS sets authorization.').
fnd('iis_authorization', []) :- xpath('/configuration/system.webServer/security/authorization', _).

% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/security/dynamicipsecurity/
% TODO: check proxy mode, this may be abused for DoS
msg('iis_dynamic_ip_security', 'INFO: IIS sets dynamic IP security (automatic blocking).').
fnd('iis_dynamic_ip_security', []) :- xpath('/configuration/system.webServer/security/dynamicIpSecurity', _).

% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/security/ipsecurity/
msg('iis_ip_restriction', 'INFO: IIS sets IP restrictions.').
fnd('iis_ip_restriction', []) :- xpath('/configuration/system.webServer/security/ipSecurity', _).

% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/security/isapicgirestriction/
msg('iis_isapi_cgi_restriction', 'INFO: IIS sets ISAPI CGI restrictions.').
fnd('iis_isapi_cgi_restriction', []) :- xpath('/configuration/system.webServer/security/isapiCgiRestriction', _).

% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/security/requestfiltering/
msg('http_server_header_shown', 'ISSUE: IIS Server header shown.').
fnd('http_server_header_shown', []) :- \+ xpath('/configuration/system.webServer/security/requestFiltering[@removeServerHeader=\'true\']', _).

% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/security/requestfiltering/alwaysallowedquerystrings/
% TODO: check clear and remove
msg('iis_request_filtering_allow_qs', 'INFO: Query string sequence allowed: {0}.').
fnd('iis_request_filtering_allow_qs', [U]) :- xpath('/configuration/system.webServer/security/requestFiltering/alwaysAllowedQueryStringSequences/add/@queryString', U).
% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/security/requestfiltering/alwaysallowedurls/
msg('iis_request_filtering_allow_url', 'INFO: URL sequence allowed: {0}.').
fnd('iis_request_filtering_allow_url', [U]) :- xpath('/configuration/system.webServer/security/requestFiltering/alwaysAllowedUrls/add/@url', U).
% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/security/requestfiltering/denyquerystringsequences/
msg('iis_request_filtering_deny_qs', 'INFO: Query string sequence denied: {0}.').
fnd('iis_request_filtering_deny_qs', [U]) :- xpath('/configuration/system.webServer/security/requestFiltering/denyQueryStringSequences/add/@sequence', U).
% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/security/requestfiltering/denyurlsequences/
msg('iis_request_filtering_deny_url', 'INFO: URL sequence denied: {0}.').
fnd('iis_request_filtering_deny_url', [U]) :- xpath('/configuration/system.webServer/security/requestFiltering/denyUrlSequences/add/@sequence', U).

% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/security/requestfiltering/fileextensions/
msg('iis_request_filtering_file_ext_denied', 'INFO: File extension denied: {0}.').
fnd('iis_request_filtering_file_ext_denied', [U]) :- xpath('/configuration/system.webServer/security/requestFiltering/fileExtensions/add[@allowed=\'false\']/@fileExtension', U).
msg('iis_request_filtering_file_ext_allowed', 'INFO: File extension allowed: {0}.').
fnd('iis_request_filtering_file_ext_allowed', [U]) :- xpath('/configuration/system.webServer/security/requestFiltering/fileExtensions/add[@allowed=\'true\']/@fileExtension', U).

% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/security/requestfiltering/filteringrules/
msg('iis_request_filtering_filter_rules', 'INFO: Request filtering rules active.').
fnd('iis_request_filtering_filter_rules', []) :- xpath('/configuration/system.webServer/security/requestFiltering/filteringRules', _).

% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/security/requestfiltering/hiddensegments/
msg('iis_request_filtering_hidden_segments', 'INFO: Hidden segments specified.').
fnd('iis_request_filtering_hidden_segments', []) :- xpath('/configuration/system.webServer/security/requestFiltering/hiddenSegments', _).

% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/security/requestfiltering/requestlimits/
msg('iis_request_filtering_request_limits', 'INFO: Request limits specified.').
fnd('iis_request_filtering_request_limits', []) :- xpath('/configuration/system.webServer/security/requestFiltering/requestLimits', _).

% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/security/requestfiltering/verbs/
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

% TODO:
% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/serverruntime
% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/serversideinclude
% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/staticcontent/
% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/tracing/
% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/urlcompression
% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/validation
% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/webdav/

% https://docs.microsoft.com/en-us/iis/configuration/system.webserver/websocket
msg('iis_websockets_enabled', 'INFO: IIS enables web sockets {0}.').
fnd('iis_websockets_enabled', ['explicitly']) :- xpath('/configuration/system.webServer/webSocket/@enabled', 'true'), !.
% default is true
fnd('iis_websockets_enabled', ['by default']) :- \+ xpath('/configuration/system.webServer/webSocket/@enabled', _).


% - glimpse[@defaultRuntimePolicy="Off"]
% - elmah
% - unencrypted db connectionstrings
% system.web/deployment[@retail='true']


finding(Message, L) :- msg(E,Message) , fnd(E,L).
fnd_type(T,M,L) :- msg(T,M), fnd(T,L).
hdr('=== {0} ===').

% report_list( [h('Build information'), nl, f('compilation_version'), f('r

report_build(M,['Build information']) :- hdr(M).
report_build('',[]).
report_build(M,L) :- fnd_type('compilation_version',M,L).
report_build(M,L) :- fnd_type('runtime_version',M,L).
report_build(M,L) :- fnd_type('version_mismatch',M,L).
report_build(M,L) :- fnd_type('debug_enabled',M,L).

report_errors(M,['Error handling']) :- hdr(M).
report_errors('',[]).
report_errors(M,L) :- fnd_type('custom_errors').

% q([M|L]) :- report_build(M,L).
% q([M|L]) :- report_errors(M,L).
q([M|L]) :- finding(M,L).



