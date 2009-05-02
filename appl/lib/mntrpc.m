Mntrpc: module
{
	PATH:	con "/dis/lib/mntrpc.dis";

	init:	fn();

	ProgMnt: con 100005;
	VersMnt: con 3;

	Mntpathmax:	con 1024;
	Mntnamemax:	con 255;
	Fhmax:	con 64;

	Mnull, Mmnt, Mdump, Mumnt, Mumntall, Mexport: con iota;
	Tmnt: adt {
		r: ref Trpc;
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

		unpack:	fn(m: ref Trpc, buf: array of byte): ref Tmnt raises (Badrpc, Badprog, Badproc, Badprocargs);
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
		r: ref Rrpc;
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
	};
};
