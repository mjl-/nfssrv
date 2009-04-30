Portmap: module
{
	PATH:	con "/dis/lib/portmap.dis";

	init:	fn();

	ProgPortmap: con 10000;

	Map: adt {
		prog:	int;
		vers:	int;
		prot:	int;
		port:	int;
	};

	Mnull, Mset, Munset, Mgetport, Mdump, Mcallit: con iota;
	Tportmap: adt {
		r: ref Trpc;
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

		unpack:	fn(m: ref Trpc, buf: array of byte): ref Tportmap raises (Badprog, Badprogversion, Badproc, Badprocargs);
	};

	Rportmap: adt {
		r: ref Rrpc;
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
	};

	portmapread:	fn(fd: ref Sys->FD): ref Tportmap raises (IO, Parse, Badrpcversion, Badprog, Badprogversion, Badproc, Badprocargs);
	portmapwrite:	fn(fd: ref Sys->FD, r: ref Rportmap): string;
};
