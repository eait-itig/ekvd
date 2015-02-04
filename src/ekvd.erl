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
-export([checksig/3, checksig/4]).

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
-define(OP_CHECKSIG, 12).

-define(DEFAULT_RETRIES, 5).

zero_truncate(Bin) ->
	case binary:split(Bin, <<0:8>>) of
		[Left, _] ->
			Left;
		[All] ->
			All
	end.

pack_request(OpNum, Key, Payload) ->
	PadBytes = (32 - byte_size(Key)),
	PayloadSize = byte_size(Payload),
	<<OpNum:8/integer, 0:8, PayloadSize:16/big, Key/binary, 0:PadBytes/unit:8, Payload/binary>>.

pack_checksig(Cookie, Uid, Sig, Data) ->
	UidSize = byte_size(Uid),
	SigSize = byte_size(Sig),
	Payload = <<UidSize, Uid/binary, SigSize, Sig/binary, Data/binary>>,
	pack_request(?OP_CHECKSIG, Cookie, Payload).

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

try_set_size(_Sock, _Atom, Exp) when Exp =< 9 ->
	error(bad_bufsize);
try_set_size(Sock, Atom, Exp) ->
	Opts = [{Atom, 1 bsl Exp}],
	case inet:setopts(Sock, Opts) of
		ok -> ok;
		_ -> try_set_size(Sock, Atom, Exp - 1)
	end.

get(_, _, 0) ->
	{error, timeout};
get(Key, Options, Attempts) ->
	{ok, Sock} = gen_udp:open(0, [binary]),
	ok = try_set_size(Sock, recbuf, 17),
	Payload = proplists:get_value(bucket, Options, <<>>),
	Req = pack_request(?OP_REQUEST, Key, Payload),

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
	get(Key, [], ?DEFAULT_RETRIES).

%% @doc Gets the value associated with a given cookie.
%% Valid options:
%% <ul>
%%   <li><code>ip_address</code> -- tuple format ip address to connect to</li>
%%   <li><code>port</code> -- integer port to connect to</li>
%%   <li><code>bucket</code> -- a bucket to provide as payload (for fakvd)</li>
%% </ul>
-spec get(Key :: binary(), Options :: proplists:proplist()) -> {ok, binary()} | {error, term()}.
get(Key, Options) ->
	Retries = proplists:get_value(retries, Options, ?DEFAULT_RETRIES),
	get(Key, Options, Retries).

checksig(_Uid, _Sig, _Data, _Opts, 0) ->
	{error, timeout};
checksig(Uid, Sig, Data, Options, Attempts) ->
	{ok, Sock} = gen_udp:open(0, [binary]),
	ok = try_set_size(Sock, sndbuf, 17),
	ok = try_set_size(Sock, recbuf, 17),
	Cookie = gen_cookie_id(),
	Req = pack_checksig(Cookie, Uid, Sig, Data),

	IpAddr = proplists:get_value(ip_address, Options, {127, 0, 0, 1}),
	Port = proplists:get_value(port, Options, 1080),
	gen_udp:send(Sock, IpAddr, Port, Req),

	receive
		{udp, Sock, _, _, Resp} ->
			case (catch unpack_request(Resp)) of
				{?OP_VALUE, Cookie, RetData} ->
					{ok, RetData};
				{?OP_NOVALUE, Cookie, _} ->
					{error, novalue};
				_Other ->
					{error, badresponse}
			end
	after 1000 ->
		checksig(Uid, Sig, Data, Options, Attempts - 1)
	end.

%% @doc Checks a machine auth signature over a given data blob.
%% Defaults to connecting to localhost on port 1080.
-spec checksig(Uid :: binary(), Signature :: binary(), Data :: binary()) -> {ok, binary()} | {error, term()}.
checksig(Uid, Sig, Data) ->
	checksig(Uid, Sig, Data, [], ?DEFAULT_RETRIES).

%% @doc Checks a machine auth signature over a given data blob.
%% Valid options:
%% <ul>
%%   <li><code>ip_address</code> -- tuple format ip address to connect to</li>
%%   <li><code>port</code> -- integer port to connect to</li>
%% </ul>
-spec checksig(Uid :: binary(), Signature :: binary(), Data :: binary(), Options :: proplists:proplist()) -> {ok, binary()} | {error, term()}.
checksig(Uid, Sig, Data, Options) ->
	Retries = proplists:get_value(retries, Options, ?DEFAULT_RETRIES),
	checksig(Uid, Sig, Data, Options, Retries).

create(_, _, 0) ->
	{error, timeout};
create(Value, Options, Attempts) ->
	{ok, Sock} = gen_udp:open(0, [binary]),
	ok = try_set_size(Sock, sndbuf, 17),
	ok = try_set_size(Sock, recbuf, 17),

	Cookie = gen_cookie_id(),
	Packet = pack_request(?OP_CREATE, Cookie, Value),

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
	create(Value, [], ?DEFAULT_RETRIES).

-spec create(Value :: binary(), Options :: proplists:proplist()) -> {ok, Key :: binary()} | {error, term()}.
create(Value, Options) ->
	Retries = proplists:get_value(retries, Options, ?DEFAULT_RETRIES),
	create(Value, Options, Retries).

update(_, _, _, 0) ->
	{error, timeout};
update(Key, Value, Options, Attempts) ->
	{ok, Sock} = gen_udp:open(0, [binary]),
	ok = try_set_size(Sock, sndbuf, 17),
	ok = try_set_size(Sock, recbuf, 17),

	Packet = pack_request(?OP_UPDATE, Key, Value),

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
	update(Key, Value, [], ?DEFAULT_RETRIES).

-spec update(Key :: binary(), Value :: binary(), Options :: proplists:proplist()) -> ok | {error, term()}.
update(Key, Value, Options) ->
	Retries = proplists:get_value(retries, Options, ?DEFAULT_RETRIES),
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
	?assertMatch(<<"abc">>, zero_truncate(<<"abc",0,"b">>)),
	?assertMatch(<<"abc">>, zero_truncate(<<"abc">>)).

gen_cookie_id_test() ->
	?assertMatch(32, byte_size(gen_cookie_id())).

-endif.
