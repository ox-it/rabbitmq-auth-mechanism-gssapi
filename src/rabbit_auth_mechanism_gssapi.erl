%% The contents of this file are subject to the Mozilla Public License
%% Version 1.1 (the "License"); you may not use this file except in
%% compliance with the License. You may obtain a copy of the License
%% at http://www.mozilla.org/MPL/
%%
%% Software distributed under the License is distributed on an "AS IS"
%% basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
%% the License for the specific language governing rights and
%% limitations under the License.
%%
%% The Original Code is RabbitMQ.
%%
%% The Initial Developer of the Original Code is GoPivotal, Inc.
%% Copyright (c) 2007-2016 Pivotal Software, Inc.  All rights reserved.
%%


-module(rabbit_auth_mechanism_gssapi).

-behaviour(rabbit_auth_mechanism).

-export([description/0, should_offer/1, init/1, handle_response/2]).

-include_lib("rabbit_common/include/rabbit.hrl").
-include_lib("public_key/include/public_key.hrl").

-rabbit_boot_step({?MODULE,
                   [{description, "auth mechanism gssapi"},
                    {mfa,         {rabbit_registry, register,
                                   [auth_mechanism, <<"GSSAPI">>, ?MODULE]}},
                    {requires,    rabbit_registry},
                    {enables,     kernel_ready},
                    {cleanup,     {rabbit_registry, unregister,
                                   [auth_mechanism, <<"GSSAPI">>]}}]}).

-record(state, {server = undefined}).

description() ->
    [{description, <<"Kerberos authentication mechanism using SASL GSSAPI">>}].

should_offer(Sock) ->
    true.

env(F) ->
    application:get_env(rabbit_auth_mechanism_gssapi, F).

init(Sock) ->
    {ok, Server} = case env(keytab) of
        {ok, Keytab} -> egssapi:start_link(Keytab);
        undefined    -> egssapi:start_link()
    end,
    #state{server=Server}.

handle_response(Response,State) ->
    case catch spnego:accept_sec_context(State#state.server, Response) of
        {ok, {Context, User, Ccname, Resp}} ->
          spnego:delete_sec_context(Context),
          {ok, #user{username       = User,
                     tags           = [],
                     authz_backends = [{rabbit_auth_backend_internal, none}]}};
        {needsmore, {Context, Resp}} -> {challenge, Resp};
        {error, Error} ->
          {refused, none, "GSSAPI error", []};
        {'EXIT', Reason} ->
          {refused, none, "GSSAPI exit", []}
    end.
