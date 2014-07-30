%%
%% ekvd
%% kvd client for erlang
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

%% @doc KVD client for Erlang.
-module(ekvd).

-export([get/1, create/2, get/2, create/1, update/2, update/3]).

-define(OP_CREATE, 0).
-define(OP_CREATED, 1).
-define(OP_REQUEST, 2).
-define(OP_VALUE, 3).
-define(OP_NOVALUE, 4).
-define(OP_DELETE, 5).
-define(OP_DELETED, 6).
-define(OP_SYNC, 7).
-define(OP_UPDATE, 10).
-define(OP_UPDATED, 11).

zero_truncate(Bin) ->
	case binary:split(Bin, <<0:8>>) of
		[Left, _] ->
			Left;
		[All] ->
			All
	end.

pack_request(OpNum, PayloadSize, Key) ->
	PadBytes = (32 - byte_size(Key)),
	<<OpNum:8/integer, 0:8, PayloadSize:16/big, Key/binary, 0:PadBytes/unit:8>>.

unpack_request(Bin) ->
	<<OpNum:8/integer, 0:8, PayloadSize:16/big, Key:32/binary-unit:8, Data/binary>> = Bin,
	if (not ((OpNum =:= ?OP_UPDATED) orelse (OpNum =:= ?OP_CREATED))
			andalso (byte_size(Data) =/= PayloadSize)) ->
		error(badpacket);
	((OpNum =:= ?OP_CREATED) andalso (byte_size(Data) =/= 32)) ->
		error(badpacket);
	(OpNum =:= ?OP_CREATED) ->
		{OpNum, zero_truncate(Key), zero_truncate(Data)};
	true ->
		{OpNum, zero_truncate(Key), Data}
	end.

get(_, _, 0) ->
	{error, timeout};
get(Key, Options, Attempts) ->
	{ok, Sock} = gen_udp:open(0, [binary]),
	Req = pack_request(?OP_REQUEST, 0, Key),

	IpAddr = proplists:get_value(ip_address, Options, {127, 0, 0, 1}),
	Port = proplists:get_value(port, Options, 1080),
	gen_udp:send(Sock, IpAddr, Port, Req),

	receive
		{udp, Sock, _, _, Resp} ->
			case (catch unpack_request(Resp)) of
				{?OP_VALUE, Key, Data} ->
					{ok, Data};
				{?OP_NOVALUE, Key, _} ->
					{error, novalue};
				_Other ->
					{error, badresponse}
			end
	after 1000 ->
		get(Key, Options, Attempts - 1)
	end.

%% @doc Gets the value associated with a given cookie.
%% Defaults to connecting to localhost on port 1080.
-spec get(Key :: binary()) -> {ok, binary()} | {error, term()}.
get(Key) ->
	get(Key, [], 3).

%% @doc Gets the value associated with a given cookie.
%% Valid options:
%% <ul>
%%   <li><code>ip_address</code> -- tuple format ip address to connect to</li>
%%   <li><code>port</code> -- integer port to connect to</li>
%% </ul>
-spec get(Key :: binary(), Options :: proplists:proplist()) -> {ok, binary()} | {error, term()}.
get(Key, Options) ->
	Retries = proplists:get_value(retries, Options, 3),
	get(Key, Options, Retries).

create(_, _, 0) ->
	{error, timeout};
create(Value, Options, Attempts) ->
	{ok, Sock} = gen_udp:open(0, [binary]),

	Cookie = gen_cookie_id(),
	Req = pack_request(?OP_CREATE, byte_size(Value), Cookie),
	Packet = <<Req/binary, Value/binary>>,

	IpAddr = proplists:get_value(ip_address, Options, {127, 0, 0, 1}),
	Port = proplists:get_value(port, Options, 1080),
	gen_udp:send(Sock, IpAddr, Port, Packet),

	receive
		{udp, Sock, _, _, Resp} ->
			case (catch unpack_request(Resp)) of
				{?OP_CREATED, Cookie, Key} ->
					{ok, Key};
				_Other ->
					{error, badresponse}
			end
	after 1000 ->
		create(Value, Options, Attempts - 1)
	end.

-spec create(Value :: binary()) -> {ok, Key :: binary()} | {error, term()}.
create(Value) ->
	create(Value, [], 3).

-spec create(Value :: binary(), Options :: proplists:proplist()) -> {ok, Key :: binary()} | {error, term()}.
create(Value, Options) ->
	Retries = proplists:get_value(retries, Options, 3),
	create(Value, Options, Retries).

update(_, _, _, 0) ->
	{error, timeout};
update(Key, Value, Options, Attempts) ->
	{ok, Sock} = gen_udp:open(0, [binary]),

	Req = pack_request(?OP_UPDATE, byte_size(Value), Key),
	Packet = <<Req/binary, Value/binary>>,

	IpAddr = proplists:get_value(ip_address, Options, {127, 0, 0, 1}),
	Port = proplists:get_value(port, Options, 1080),
	gen_udp:send(Sock, IpAddr, Port, Packet),

	receive
		{udp, Sock, _, _, Resp} ->
			case (catch unpack_request(Resp)) of
				{?OP_UPDATED, Key, _} ->
					ok;
				_Other ->
					{error, badresponse}
			end
	after 1000 ->
		update(Key, Value, Options, Attempts - 1)
	end.

-spec update(Key :: binary(), Value :: binary()) -> ok | {error, term()}.
update(Key, Value) ->
	update(Key, Value, [], 3).

-spec update(Key :: binary(), Value :: binary(), Options :: proplists:proplist()) -> ok | {error, term()}.
update(Key, Value, Options) ->
	Retries = proplists:get_value(retries, Options, 3),
	update(Key, Value, Options, Retries).

% Generate a random 32-byte url-safe string as a request cookie
gen_cookie_id() ->
	Bytes = crypto:strong_rand_bytes(24),
	Base = base64:encode(Bytes),
	Base2 = binary:replace(Base, <<"/">>, <<"_">>, [global]),
	binary:replace(Base2, <<"+">>, <<"-">>, [global]).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

zero_truncate_test() ->
	?assertMatch(<<"abc">>, zero_truncate(<<"abc",0,"b">>)).

-endif.