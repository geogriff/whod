%%%-------------------------------------------------------------------
%% @doc whod top level supervisor.
%% @end
%%%-------------------------------------------------------------------

-module(whod_sup).

-behaviour(supervisor).

%% API
-export([start_link/0]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

%%====================================================================
%% API functions
%%====================================================================

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%%====================================================================
%% Supervisor callbacks
%%====================================================================

%% Child :: {Id,StartFunc,Restart,Shutdown,Type,Modules}
init([]) ->
    Mods = [whod_server],
    ChildSpecs = [Mod:child_spec() || Mod <- Mods],
    {ok, { {one_for_one, 5, 1}, ChildSpecs} }.

%%====================================================================
%% Internal functions
%%====================================================================
