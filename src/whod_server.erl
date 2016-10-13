-module(whod_server).

-behaviour(gen_server).

-include("whod_log.hrl").

%% api
-export([child_spec/0, start_link/0]).

%% gen_server
-export([init/1,
	 handle_call/3,
	 handle_cast/2,
	 handle_info/2,
	 terminate/2,
	 code_change/3
	]).

-define(TYPE_NS, 2).
-define(TYPE_TXT, 16).

-define(CLASS_IN, 1).

-define(QCLASS_ANY, 255).

-define(OPCODE_QUERY, 0).

-define(RCODE_NOERROR, 0).
-define(RCODE_FORMAT, 1).
-define(RCODE_SERVFAIL, 2).
-define(RCODE_NXDOMAIN, 3).
-define(RCODE_REFUSED, 5).

-record(state, {
	  sock4 :: pid() | port(),
	  sock6 :: pid() | port() | undefined,
	  names :: [[binary()]],
	  answered = 0 :: non_neg_integer(),
	  invalid = 0 :: non_neg_integer(),
	  not_found = 0 :: non_neg_integer(),
	  refused = 0 :: non_neg_integer(),
	  sock_errors = 0 :: non_neg_integer()
	 }).

child_spec() ->
    #{id => ?MODULE,
      start => {?MODULE, start_link, []},
      restart => transient,
      shutdown => infinity,
      type => worker,
      modules => [?MODULE]}.

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

init([]) ->
    ?LOG_I("whod_server starting on node ~p", [node()]),
    RawNames = application:get_env(whod, names, []),
    Names = lists:map(fun (Name) -> binary:split(list_to_binary(Name), <<$.>>, [global, trim]) end,
		      RawNames),
    ListenIp4 = application:get_env(whod, listen_ip4, {127,0,0,1}),
    ListenIp6 = application:get_env(whod, listen_ip6, {0,0,0,0,0,0,0,1}),
    ListenPort = application:get_env(whod, listen_port, 6001),
    Opts = [binary, {active, true}, {reuseaddr, true}],
    case gen_udp:open(ListenPort, Opts ++ [inet, {ip, ListenIp4}]) of
	{ok, Sock4} ->
	    case gen_udp:open(ListenPort, Opts ++ [inet6, {ipv6_v6only, true}, {ip, ListenIp6}]) of
		{ok, Sock6} ->
		    {ok, #state{sock4 = Sock4, sock6 = Sock6, names = Names}};
		{error, Sock6Err} ->
		    ?LOG_W("error listening on ipv6, but continuing anyway: ~1000p", [Sock6Err]),
		    {ok, #state{sock4 = Sock4, names = Names}}
	    end;
	{error, Sock4Err} ->
	    ?LOG_E("error listening on ipv4: ~1000p", [Sock4Err]),
	    {stop, {open_error, Sock4Err}, undefined}
    end.

handle_call(Msg, _From, State) ->
    ?LOG_W("unknown call: ~1000p", [Msg]),
    {reply, ok, State}.

handle_cast(Msg, State) ->
    ?LOG_W("unknown cast: ~1000p", [Msg]),
    {noreply, State}.

handle_info({udp, Sock, Ip, Port, Packet}, State) ->
    {_Res, NewState} = handle_dns_packet(Packet, Sock, Ip, Port, State),
    {noreply, NewState};

handle_info(Msg, State) ->
    ?LOG_W("unknown msg: ~1000p", [Msg]),
    {noreply, State}.

terminate(Reason, State) ->
    ?LOG_W("whod_server stopping for reason: ~1000p", [Reason]),
    case State of
	#state{sock4 = Sock4, sock6 = Sock6} ->
	    gen_udp:close(Sock4),
	    case Sock6 of
		undefined ->
		    ok;
		_ ->
		    gen_udp:close(Sock6)
	    end;
	undefined ->
	    ok
    end,
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%
%% private stuff
%%

handle_dns_packet(<< ID:2/bytes,
		     0:1, ?OPCODE_QUERY:4, _AA:1, 0:1, RD:1, _RA:1, _Z:1, _AD:1, _CD:1, _RCODE:4,
		     1:16, 0:16, 0:16, ARCOUNT:16,
		     Data/binary >>=MsgData,
		  Sock, Ip, Port, State)
  when ARCOUNT == 0 orelse ARCOUNT == 1 ->
    IpStr = inet:ntoa(Ip),
    case parse_dns_question(Data, MsgData) of
	{ok, QTYPE, QNAME, ARData} ->
	    QDDataSize = size(Data) - size(ARData),
	    << QDData:QDDataSize/binary, _/binary >> = Data,
	    case {lists:member(QNAME, State#state.names), QTYPE} of
		{true, ?TYPE_TXT} ->
		    %% answer to query
		    ANData = [<< 3:2, 12:14,           %% NAME (offset to QNAME)
				 ?TYPE_TXT:16,         %% TYPE
				 ?CLASS_IN:16,         %% CLASS
				 0:32,                 %% TTL
				 (length(IpStr)+1):16, %% RDLENGTH

				 %% RDATA (TXT-DATA)
				 (length(IpStr)):8 >>, %% string length
			      IpStr                    %% string
			     ],
		    ?ACCESS_LOG("NOERROR ip [~s] name [~s] type [TXT]",
				[IpStr, [ [Label, $.] || Label <- QNAME]]),
		    send_resp(ID, ?OPCODE_QUERY, RD, ?RCODE_NOERROR,
			      [QDData], [ANData], [], [],
			      Sock, Ip, Port,
			      State#state{answered = State#state.answered + 1});
		{true, ?TYPE_NS} ->
		    [QNAMEHost | _] = QNAME, %% QNAME is assumed not to be dns root
		    NSDNAME =
			<< 0:2, 2:6, "ns",
			   %% offset to second label of QNAME
			   3:2, (12 + 1 + size(QNAMEHost)):14
			>>,
		    ANData =
			<< 3:2, 12:14,           %% NAME (offset to QNAME)
			   ?TYPE_NS:16,          %% TYPE
			   ?CLASS_IN:16,         %% CLASS
			   7200:32,              %% TTL
			   (size(NSDNAME)):16,   %% RDLENGTH
			   NSDNAME/binary        %% RDATA
			>>,
		    ?ACCESS_LOG("NOERROR ip [~s] name [~s] type [NS]",
				[IpStr, [ [Label, $.] || Label <- QNAME]]),
		    send_resp(ID, ?OPCODE_QUERY, RD, ?RCODE_NOERROR,
			      [QDData], [ANData], [], [],
			      Sock, Ip, Port,
			      State#state{answered = State#state.answered + 1});
		{true, QTYPE} ->
		    ?ACCESS_LOG("NXDOMAIN ip [~s] name [~s] type [~B]",
				[IpStr, [ [Label, $.] || Label <- QNAME], QTYPE]),
		    {_, NewState} =
			send_resp(ID, ?OPCODE_QUERY, RD, ?RCODE_NXDOMAIN,
				  [QDData], [], [], [],
				  Sock, Ip, Port,
				  State#state{not_found = State#state.not_found + 1}),
		    {{error, not_found}, NewState};
		{false, QTYPE} ->
		    ?ACCESS_LOG("REFUSED ip [~s] name [~s] type [~B]",
				[IpStr, [ [Label, $.] || Label <- QNAME], QTYPE]),
		    {_, NewState} =
			send_resp(ID, ?OPCODE_QUERY, RD, ?RCODE_REFUSED,
				  [QDData], [], [], [],
				  Sock, Ip, Port,
				  State#state{refused = State#state.refused + 1}),
		    {{error, refused}, NewState}
	    end;
	{error, ParseErr} ->
	    ?ACCESS_LOG("FORMAT ip [~s] error [~1000p]", [IpStr, ParseErr]),
	    {_, ParseErrState} =
		send_resp(ID, ?OPCODE_QUERY, RD, ?RCODE_FORMAT,
			  [], [], [], [],
			  Sock, Ip, Port,
			  State#state{invalid = State#state.invalid + 1}),
	    {{error, ParseErr}, ParseErrState}
    end;
handle_dns_packet(<< ID:16,
		     QR:1, OPCODE:4, AA:1, TC:1, RD:1, RA:1, Z:1, AD:1, CD:1, RCODE:4,
		     QDCOUNT:16, ANCOUNT:16, NSCOUNT:16, ARCOUNT:16,
		     Data/binary >>,
		  Sock, Ip, Port, State) ->
    ?LOG_D("unhandled or invalid packet:~n"
	   "<< ID=~B,~n"
	   "   QR=~B, Opcode=~B, AA=~B, TC=~B, RD=~B, RA=~B, Z=~B, AD=~B, CD=~B, RCODE=~B~n"
	   "   QDCOUNT=~B, ADCOUNT=~B, NSCOUNT=~B, ARCOUNT=~B,~n"
	   "   Data:~B/binary >>",
	   [ID, QR, OPCODE, AA, TC, RD, RA, Z, AD, CD, RCODE,
	    QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT, size(Data)]),
    IpStr = inet:ntoa(Ip),
    ?ACCESS_LOG("FORMAT ip [~s] error [bad_query]",[IpStr]),
    {_, NewState} =
	send_resp(ID, OPCODE, RD, ?RCODE_FORMAT,
		  [], [], [], [],
		  Sock, Ip, Port,
		  State#state{invalid = State#state.invalid + 1}),
    {{error, bad_query}, NewState};

handle_dns_packet(_Data, _Sock, Ip, _Port, State) ->
    IpStr = inet:ntoa(Ip),
    ?ACCESS_LOG("FORMAT ip [~s] error [bad_packet]",[IpStr]),
    {{error, bad_packet}, State#state{invalid = State#state.invalid + 1}}.

send_resp(ID, OPCODE, RD, RCODE, QDData, ANData, NSData, ARData,
	   Sock, Ip, Port, State) ->
    AA = case RCODE of
	     ?RCODE_NOERROR -> 1;
	     ?RCODE_NXDOMAIN -> 1;
	     _ -> 0
	 end,
    Resp = [%% header
	    ID,
	    << 1:1, OPCODE:4, AA:1, 0:1, RD:1, 0:1, 0:1, AA:1, 0:1, RCODE:4,
	       (length(QDData)):16, (length(ANData)):16,
	       (length(NSData)):16, (length(ARData)):16 >>,
	    QDData, ANData, NSData, ARData
	   ],
    case gen_udp:send(Sock, Ip, Port, Resp) of
	ok ->
	    {ok, State};
	{error, SendErr} ->
	    ?LOG_W("error sending response: ~1000p", [SendErr]),
	    {{error, SendErr}, State#state{sock_errors = State#state.sock_errors + 1}}
    end.

parse_dns_question(Data, MsgData) ->
    case parse_dns_name(Data, MsgData, []) of
	{ok, QNAME, << QTYPE:16, ?CLASS_IN:16, Rest/binary >>} ->
	    {ok, QTYPE, QNAME, Rest};
	{ok, _, _} ->
	    {error, bad_question};
	{error, Err} ->
	    {error, Err}
    end.

parse_dns_name(<< 0:8, _/binary >>, {ptr, Rest}, QNAME) ->
    {ok, lists:reverse(QNAME), Rest};
parse_dns_name(<< 0:8, Rest/binary >>, _MsgData, QNAME) ->
    {ok, lists:reverse(QNAME), Rest};
parse_dns_name(<< 0:2, LabelLen:6, Label:LabelLen/bytes, Rest/binary >>,
		    MsgData, QNAME) ->
    parse_dns_name(Rest, MsgData, [Label | QNAME]);
%% compression scheme
parse_dns_name(<< 3:2, OFFSET:14, Rest/binary >>, MsgData, QNAME) ->
    case MsgData of
	<< _:OFFSET/bytes, NewData/binary >> ->
	    parse_dns_name(NewData, {ptr, Rest}, QNAME);
	_ ->
	    {error, bad_reference}
    end;
parse_dns_name(_Data, _MsgData, _QNAME) ->
    {error, bad_question}.
