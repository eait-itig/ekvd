%%
%% ekvd
%% kvd client for erlang
%%
%% Copyright 2012-2015 Alex Wilson <alex@uq.edu.au>
%% The University of Queensland
%% All rights reserved.
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions
%% are met:
%% 1. Redistributions of source code must retain the above copyright
%%    notice, this list of conditions and the following disclaimer.
%% 2. Redistributions in binary form must reproduce the above copyright
%%    notice, this list of conditions and the following disclaimer in the
%%    documentation and/or other materials provided with the distribution.
%%
%% THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
%% IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
%% OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
%% IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
%% NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
%% DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
%% THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
%% (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
%% THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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

-define(CS_HMAC_SHA1, 1).
-define(CS_HMAC_SHA256, 2).
-define(CS_RSA_SHA1, 3).
-define(CS_RSA_SHA256, 4).

-type ip() :: tuple().
-type sig_algo() :: hmac_sha1 | hmac_sha256 | rsa_sha1 | rsa_sha256.
-type option() :: {retries, integer()} | {ip_address, ip()} | {port, integer()} | {bucket, binary()} | {algorithm, sig_algo()}.
-type options() :: [option()].
-export_type([options/0, option/0]).

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

pack_checksig(Cookie, Uid, Algo, Sig, Data) ->
	UidSize = byte_size(Uid),
	SigSize = byte_size(Sig),
	Payload = <<UidSize, Uid/binary, Algo, SigSize, Sig/binary, Data/binary>>,
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
	Timeout = proplists:get_value(timeout, Options, 100),
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
	after Timeout ->
		Options2 = lists:keystore(timeout, 1, Options, {timeout, Timeout*2}),
		get(Key, Options2, Attempts - 1)
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
%%   <li><code>timeout</code> -- initial timeout in ms, will be doubled at each retry. default 100</li>
%%   <li><code>retries</code> -- number of retries</li>
%% </ul>
-spec get(Key :: binary(), Options :: options()) -> {ok, binary()} | {error, term()}.
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
	AlgoAtom = proplists:get_value(algorithm, Options, hmac_sha1),
	Algo = case AlgoAtom of
		hmac_sha1 -> ?CS_HMAC_SHA1;
		hmac_sha256 -> ?CS_HMAC_SHA256;
		rsa_sha1 -> ?CS_RSA_SHA1;
		rsa_sha256 -> ?CS_RSA_SHA256
	end,
	Req = pack_checksig(Cookie, Uid, Algo, Sig, Data),

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
%%   <li><code>algorithm</code> -- algorithm used to verify signature</li>
%% </ul>
-spec checksig(Uid :: binary(), Signature :: binary(), Data :: binary(), Options :: options()) -> {ok, binary()} | {error, term()}.
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

-spec create(Value :: binary(), Options :: options()) -> {ok, Key :: binary()} | {error, term()}.
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

-spec update(Key :: binary(), Value :: binary(), Options :: options()) -> ok | {error, term()}.
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
