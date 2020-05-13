
msg('no_auth', 'No authentication specified.').
fnd('no_auth',[]) :- \+ xpath('/configuration/system.web/authentication',_).

msg('auth_mode', 'Authentication mode used: %1').
fnd('auth_mode', [Mode]) :- xpath('/configuration/system.web/authentication[mode]',Mode).




finding(Message, L) :- msg(E,Message) , fnd(E,L).

q([M|L]) :- finding(M,L).



