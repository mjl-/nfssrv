Mntrpc: module
{
	PATH:	con "/dis/lib/mntrpc.dis";

	init:	fn();

	ProgMnt: con 10005;
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

	MNT3ok:		con 0;
	MNT3perm:	con 1;
	MNT3noent:	con 2;
	MNT3io:		con 5;
	MNT3access:	con 13;
	MNT3notdir:	con 20;
	MNT3inval:	con 22;
	MNT3nametoolong:	con 63;
	MNT3notsupp:	con 10004;
	MNT3serverfault:	con 10006;

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
			# following only present if status is MNT3ok
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
