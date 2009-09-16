Mntrpc: module
{
	PATH:	con "/dis/lib/mntrpc.dis";

	init:	fn();
	dflag:	int;

	ProgMnt: con 100005;
	VersMnt: con 3;

	Mntpathmax:	con 1024;
	Mntnamemax:	con 255;
	Fhmax:	con 64;

	mnttags: array of string;

	Mnull, Mmnt, Mdump, Mumnt, Mumntall, Mexport: con iota;
	Tmnt: adt {
		r: ref Sunrpc->Trpc;
		pick {
		Null =>
		Mnt =>
			dirpath:	string;
		Dump =>
		Umnt =>
			dirpath:	string;
		Umntall =>
		Export =>
		}

		size:	fn(m: self ref Tmnt): int;
		pack:	fn(m: self ref Tmnt, buf: array of byte, o: int): int;
		unpack:	fn(m: ref Sunrpc->Trpc, buf: array of byte): ref Tmnt raises (Badrpc, Badprog, Badproc, Badprocargs);
	};

	Eok:		con 0;
	Eperm:	con 1;
	Enoent:	con 2;
	Eio:		con 5;
	Eaccess:	con 13;
	Enotdir:	con 20;
	Einval:	con 22;
	Enametoolong:	con 63;
	Enotsupp:	con 10004;
	Eserverfault:	con 10006;

	Export: adt {
		dir:	string;
		groups:	array of string;
	};

	Rmnt: adt {
		r: ref Sunrpc->Rrpc;
		pick {
		Null =>
		Mnt =>
			status:	int;
			# following only present if status is Eok
			fh:	array of byte;
			auths:	array of int;
		Dump =>
			mountlist:	array of (string, string); # hostname, directory
		Umnt =>
		Umntall =>
		Export =>
			exports:	array of Export;
		}

		size:	fn(m: self ref Rmnt): int;
		pack:	fn(m: self ref Rmnt, buf: array of byte, o: int): int;
		unpack:	fn(tm: ref Sunrpc->Trpc, rm: ref Sunrpc->Rrpc, buf: array of byte): ref Rmnt raises (Badrpc, Badproc, Badprocargs);
	};
};
