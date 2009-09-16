Portmaprpc: module
{
	PATH:	con "/dis/lib/portmaprpc.dis";

	init:	fn();
	dflag:	int;

	ProgPortmap: con 100000;
	VersPortmap: con 2;
	Mnull, Mset, Munset, Mgetport, Mdump, Mcallit: con iota;

	portmaptags: array of string;

	Map: adt {
		prog:	int;
		vers:	int;
		prot:	int;
		port:	int;
	};

	Tportmap: adt {
		r: ref Sunrpc->Trpc;
		pick {
		Null =>
		Set or
		Unset or
		Getport =>
			map:	Map;
		Dump =>
		Callit =>
			prog:	int;
			vers:	int;
			proc:	int;
			args:	array of byte;
		}

		size:	fn(m: self ref Tportmap): int;
		pack:	fn(m: self ref Tportmap, buf: array of byte, o: int): int;
		unpack:	fn(m: ref Sunrpc->Trpc, buf: array of byte): ref Tportmap raises (Badrpc, Badprog, Badproc, Badprocargs);
	};

	Rportmap: adt {
		r: ref Sunrpc->Rrpc;
		pick {
		Null =>
		Set or
		Unset =>
			bool:	int;
		Getport =>
			port:	int;
		Dump =>
			maps:	array of Map;
		Callit =>
			port:	int;
			res:	array of byte;
		}

		size:	fn(m: self ref Rportmap): int;
		pack:	fn(m: self ref Rportmap, buf: array of byte, o: int): int;
		unpack:	fn(t: ref Sunrpc->Trpc, rr: ref Sunrpc->Rrpc, buf: array of byte): ref Rportmap raises (Badrpc, Badproc, Badprocargs);
	};
};
