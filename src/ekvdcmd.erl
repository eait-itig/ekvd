-module(ekvdcmd).
-export([main/1]).

main(Args) ->
	Opts = [
		{host, "h", "host", string},
		{port, "p", "port", string},
		{retries, "r", "retries", integer},
		{bucket, "b", "bucket", string}
	],
	Args2 = getopt(Args, Opts, []),
	{OptArgs, ArgArgs} = lists:partition(fun(K) -> is_tuple(K) end, lists:reverse(Args2)),
	OptArgs2 = case proplists:get_value(bucket, OptArgs) of
		undefined -> OptArgs;
		StrBucket -> lists:keyreplace(bucket, 1, OptArgs, {bucket, list_to_binary(StrBucket)})
	end,
	OptArgs3 = case proplists:get_value(host, OptArgs2) of
		undefined -> OptArgs2;
		StrHost -> case inet:getaddr(StrHost, inet) of
			{ok, Ip} when is_tuple(Ip) -> [{ip_address, Ip} | OptArgs2];
			_ -> io:format("failed to look up ~w\n", [StrHost]), halt(1)
		end
	end,
	main_opt(ArgArgs, OptArgs3).

getopt([], _Opts, Args) -> Args;
getopt([[$-, $- | K], V | Rest], Opts, Args) ->
	case lists:keyfind(K, 3, Opts) of
		{Atom, _Short, K, string} ->
			getopt(Rest, Opts, [{Atom, V} | Args]);
		{Atom, _Short, K, integer} ->
			getopt(Rest, Opts, [{Atom, list_to_integer(V)} | Args]);
		{Atom, _Short, K, Atom} when (Atom =:= false) or (Atom =:= undefined) ->
			getopt([V | Rest], Opts, [{Atom, true} | Args]);
		false ->
			io:format("unknown option --~w\n", [K]),
			halt(1)
	end;
getopt([[$- | K], V | Rest], Opts, Args) ->
	case lists:keyfind(K, 2, Opts) of
		{Atom, K, _Long, string} ->
			getopt(Rest, Opts, [{Atom, V} | Args]);
		{Atom, K, _Long, integer} ->
			getopt(Rest, Opts, [{Atom, list_to_integer(V)} | Args]);
		{Atom, K, _Long, Atom} when (Atom =:= false) or (Atom =:= undefined) ->
			getopt([V | Rest], Opts, [{Atom, true} | Args]);
		false ->
			io:format("unknown option -~w\n", [K]),
			halt(1)
	end;
getopt([Next | Rest], Opts, Args) ->
	getopt(Rest, Opts, [Next | Args]).

main_opt(["get", Key], Opts) ->
	case ekvd:get(list_to_binary(Key), Opts) of
		{ok, Data} -> io:format("~s\n", [Data]);
		{error, Term} -> io:format("ERROR: ~p\n", [Term]), halt(1)
	end;
main_opt(["create", Val], Opts) ->
	case ekvd:create(list_to_binary(Val), Opts) of
		{ok, Key} -> io:format("~s\n", [Key]);
		{error, Term} -> io:format("ERROR: ~p\n", [Term]), halt(1)
	end;
main_opt(["update", Key, Val], Opts) ->
	case ekvd:update(list_to_binary(Key), list_to_binary(Val), Opts) of
		ok -> io:format("ok\n");
		{error, Term} -> io:format("ERROR: ~p\n", [Term]), halt(1)
	end;
main_opt(["checksig", Uid, "secret:" ++ Secret64, Data64], Opts) ->
	Data = base64:decode(Data64),
	Sig = crypto:hmac(sha, base64:decode(Secret64), Data),
	case ekvd:checksig(list_to_binary(Uid), Sig, Data, Opts) of
		{ok, RetData} -> io:format("~s\n", [RetData]);
		{error, Term} -> io:format("ERROR: ~p\n", [Term]), halt(1)
	end;
main_opt(["checksig", Uid, Sig64, Data64], Opts) ->
	Data = base64:decode(Data64),
	Sig = base64:decode(Sig64),
	case ekvd:checksig(list_to_binary(Uid), Sig, Data, Opts) of
		{ok, RetData} -> io:format("~s\n", [RetData]);
		{error, Term} -> io:format("ERROR: ~p\n", [Term]), halt(1)
	end;
main_opt(_, _Opts) ->
	io:format("usage: ekvdcmd [opts] get <key>\n"),
	io:format("                      create <value>\n"),
	io:format("                      update <key> <value>\n"),
	io:format("                      checksig <uid> secret:<base64secret> <base64data>\n"),
	io:format("                      checksig <uid> <base64sig> <base64data>\n"),
	io:format("options: -h|--host [hostname|ip]\n"),
	io:format("         -p|--port [port]\n"),
	io:format("         -r|--retries [num]\n"),
	io:format("         -b|--bucket [bucket]\n"),
	halt(1).
