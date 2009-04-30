Sunrpc: module
{
	PATH:	con "/dis/lib/sunrpc.dis";

	init:	fn();

	IO:	exception(string);
	Parse:	exception(string);
	Badrpcversion:	exception;
	Badprog:	exception;
	Badprogversion:	exception;
	Badproc:	exception;
	Badprocargs:	exception;

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

	Trpc: adt {
		xid:	int;
		rpcvers:	int;
		prog:	int;
		vers:	int;
		proc:	int;
		cred:	Auth;
		verf:	Auth;
		# program-specific request
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

	rpcwrite:	fn(fd: ref Sys->FD, r: ref Rrpc): string;

	p32:	fn(d: array of byte, o: int, v: int): int;
	popaque:	fn(d: array of byte, o: int, buf: array of byte): int;
	g32:	fn(d: array of byte, o: int): (int, int) raises (Parse);
	gopaque:	fn(buf: array of byte, o: int, max: int): (array of byte, int) raises (Parse);
};
