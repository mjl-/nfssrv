Sunrpc: module
{
	PATH:	con "/dis/lib/sunrpc.dis";

	init:	fn();
	dflag:	int;

	Rpcversion:	con 2;

	Parse:	exception(string);
	Badrpcversion:	exception;
	Badprog:	exception;
	Badproc:	exception;
	Badprocargs:	exception(string);
	Badrpc:		exception(string, ref Trpc, ref Rrpc);

	MTcall, MTreply: con iota;
	MSGaccepted, MSGdenied: con iota;

	ACsuccess,
	ACprogunavail,
	ACprogmismatch,
	ACprocunavail,
	ACgarbageargs,
	ACsystemerr:	con iota;

	RSrpcmismatch, RSautherror: con iota;

	AUok,
	AUbadcred,
	AUrejectedcred,
	AUbadverf,
	AUrejectedverf,
	AUtooweak,
	AUinvalidresp,
	AUfailed:	con iota;


	Anone, Asys, Sshort: con iota;
	Authmax: con 400;
	Auth: adt {
		which:	int;
		buf:	array of byte;

		size:	fn(a: self Auth): int;
		pack:	fn(a: self Auth, buf: array of byte, o: int): int;
	};

	Authsys: adt {
		stamp:	int;
		machine:	string;
		uid,
		gid:	int;
		gids:	array of int;

		size:	fn(a: self ref Authsys): int;
		pack:	fn(a: self ref Authsys, buf: array of byte, o: int): int;
		unpack:	fn(buf: array of byte, o: int): ref Authsys raises (Parse);
	};

	Trpc: adt {
		xid:	int;
		rpcvers:	int;
		prog:	int;
		vers:	int;
		proc:	int;
		cred:	Auth;
		verf:	Auth;
		# program-specific request

		size:	fn(m: self ref Trpc): int;
		pack:	fn(m: self ref Trpc, buf: array of byte, o: int): int;
	};

	Rrpc: adt {
		xid:	int;
		pick {
		Success =>
			verf:	Auth;
			# program-specific response
		Progmismatch =>
			verf:	Auth;
			low, high:	int;
		Badprog or
		Badproc or
		Badprocargs or
		Systemerr =>
			verf:	Auth;

		Rpcmismatch =>
			low, high:	int;
		Autherror =>
			error:	int;
		}

		size:	fn(m: self ref Rrpc): int;
		pack:	fn(m: self ref Rrpc, buf: array of byte, o: int): int;
	};

	readmsg:	fn(fd: ref Sys->FD): (array of byte, string);
	parsereq:	fn[T](buf: array of byte, m: T): T
		for {
		T =>	unpack:	fn(m: ref Trpc, buf: array of byte): T raises (Badrpc, Badprog, Badproc, Badprocargs);
		}
		raises (Parse, Badrpc);
	parseresp:	fn[T](tm: ref Trpc, buf: array of byte, m: T): T
		for {
		T =>	unpack:	fn(tm: ref Trpc, rm: ref Rrpc, buf: array of byte): T raises (Badrpc, Badproc, Badprocargs);
		}
		raises (Parse, Badrpc);
	writerpc:	fn[T](fd: ref Sys->FD, pre: array of byte, wrapmsg: int, m: T): string
		for {
		T =>	size:	fn(m: T): int;
			pack:	fn(m: T, buf: array of byte, o: int): int;
		};

	p32:		fn(d: array of byte, o: int, v: int): int;
	p64:		fn(d: array of byte, o: int, v: big): int;
	popaque:	fn(d: array of byte, o: int, buf: array of byte): int;
	popaquefixed:	fn(d: array of byte, o: int, buf: array of byte): int;
	pstr:		fn(d: array of byte, o: int, s: string): int;
	pbool:		fn(d: array of byte, o: int, v: int): int;
	pboolopaque:	fn(d: array of byte, o: int, buf: array of byte): int;

	gbool:		fn(d: array of byte, o: int): (int, int) raises (Parse);
	g32:		fn(d: array of byte, o: int): (int, int) raises (Parse);
	g64:		fn(d: array of byte, o: int): (big, int) raises (Parse);
	gopaque:	fn(buf: array of byte, o: int, max: int): (array of byte, int) raises (Parse);
	gopaquefixed:	fn(buf: array of byte, o: int, n: int): (array of byte, int) raises (Parse);
	gstr:		fn(buf: array of byte, o: int, max: int): (string, int) raises (Parse);
};
