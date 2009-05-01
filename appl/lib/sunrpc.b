implement Sunrpc;

include "sys.m";
	sys: Sys;
	sprint: import sys;
include "sunrpc.m";

init()
{
	sys = load Sys Sys->PATH;
}


write[T](fd: ref Sys->FD, m: T): string
	for {
	T =>	size:   fn(m: T): int;
		pack:	fn(m: T, buf: array of byte, o: int): int;
	}
{
	size := m.size(m);
	buf := array[4+size] of byte;
	o := 0;
	o = p32(buf, o, (1<<31)|size);
	o = m.pack(m, buf, o);
	if(sys->write(fd, buf, len buf) != len buf)
		return sprint("write: %r");
	return nil;
}

readmsg(fd: ref Sys->FD): array of byte raises (IO, Parse)
{
say("reading Trpc");
	buf := array[0] of byte;
	for(;;) {
		sbuf := array[4] of byte;
		if(sys->readn(fd, sbuf, len sbuf) != len sbuf)
			raise IO("short read");
		v := g32(sbuf, 0).t0;
		end := v&(1<<31);
		v &= ~end;
		if(v > 64*1024)
			raise Parse("message too long");
say(sprint("Trpc, fragment, length %d, end %d", v, end));

		nbuf := array[len buf+v] of byte;
		nbuf[:] = buf;
		if(sys->readn(fd, nbuf[len buf:], v) != v)
			raise IO("short read");
		buf = nbuf;

		if(end)
			break;
	}
say(sprint("Trpc, have request, length %d", len buf));
	return buf;
}

read[T](fd: ref Sys->FD, m: T): T
	for {
	T =>	unpack: fn(m: ref Trpc, buf: array of byte): T raises (Badrpc, Badprog, Badproc, Badprocargs);
	}
	raises (IO, Parse, Badrpc)
{
	r := ref Trpc;
	nullverf: Auth;
	nullverf.which = Anone;
	{
		buf := readmsg(fd);

		o := 0;
		(r.xid, o) = g32(buf, o);
		msgtype: int;
		(msgtype, o) = g32(buf, o);
		if(msgtype != MTcall)
			raise Parse("message rpc response, expected rpc request");
		(r.rpcvers, o) = g32(buf, o);
		if(r.rpcvers != 2)
			raise Badrpcversion();
		(r.prog, o) = g32(buf, o);
		(r.vers, o) = g32(buf, o);
		(r.proc, o) = g32(buf, o);
		(r.cred.which, o) = g32(buf, o);
		(r.cred.buf, o) = gopaque(buf, o, Authmax);
		(r.verf.which, o) = g32(buf, o);
		(r.verf.buf, o) = gopaque(buf, o, Authmax);
		return m.unpack(r, buf[o:]);
	} exception e {
	IO or
	Parse =>
		raise;
	Badrpcversion =>
		raise Badrpc (nil, ref Rrpc.Rpcmismatch (r.xid, 2, 2));

	Badrpc =>
		pick out := e.t1 {
		Progmismatch =>
			out.verf = nullverf;
		}
		raise;
	Badprog =>
		raise Badrpc (nil, ref Rrpc.Badprog (r.xid, nullverf));
	Badproc =>
		raise Badrpc (nil, ref Rrpc.Badproc (r.xid, nullverf));
	Badprocargs =>
		raise Badrpc (nil, ref Rrpc.Badprocargs (r.xid, nullverf));
	}
}


Auth.size(a: self Auth): int
{
	return 4+4+len a.buf;
}

Auth.pack(a: self Auth, buf: array of byte, o: int): int
{
	o = p32(buf, o, a.which);
	o = popaque(buf, o, a.buf);
	return o;
}

Rrpc.size(mm: self ref Rrpc): int
{
	return mm.pack(nil, 0);
}

Rrpc.pack(mm: self ref Rrpc, buf: array of byte, o: int): int
{
	o = p32(buf, o, mm.xid);
	o = p32(buf, o, MTreply);
	pick m := mm {
	Success =>
		o = p32(buf, o, MSGaccepted);
		o = m.verf.pack(buf, o);
		o = p32(buf, o, ACsuccess);
	Progmismatch =>
		o = p32(buf, o, MSGaccepted);
		o = m.verf.pack(buf, o);
		o = p32(buf, o, ACprogmismatch);
		o = p32(buf, o, m.low);
		o = p32(buf, o, m.high);
	Badprog or
	Badproc or
	Badprocargs or
	Systemerr =>
		o = p32(buf, o, MSGaccepted);
		o = m.verf.pack(buf, o);
		pick m0 := mm {
		Badprog =>	o = p32(buf, o, ACprogunavail);
		Badproc =>	o = p32(buf, o, ACprocunavail);
		Badprocargs =>	o = p32(buf, o, ACgarbageargs);
		Systemerr =>	o = p32(buf, o, ACsystemerr);
		}
	Rpcmismatch =>
		o = p32(buf, o, MSGdenied);
		o = p32(buf, o, RSrpcmismatch);
		o = p32(buf, o, m.low);
		o = p32(buf, o, m.high);
	Autherror =>
		o = p32(buf, o, MSGdenied);
		o = p32(buf, o, RSautherror);
		o = p32(buf, o, m.error);
	* =>	raise "internal error";
	}
	return o;
}


p32(d: array of byte, o: int, v: int): int
{
	if(d == nil)
		return o+4;
	d[o++] = byte (v>>24);
	d[o++] = byte (v>>16);
	d[o++] = byte (v>>8);
	d[o++] = byte (v>>0);
	return o;
}

popaque(d: array of byte, o: int, buf: array of byte): int
{
	if(d == nil)
		return o+4+len buf;
	o = p32(d, o, len buf);
	d[o:] = buf;
	o += len buf;
	return o;
}

pstr(d: array of byte, o: int, s: string): int
{
	if(d == nil)
		return o+4+len array of byte s;
	buf := array of byte s;
	o = p32(d, o, len buf);
	d[o:] = buf;
	o += len buf;
	return o;
}

g32(d: array of byte, o: int): (int, int) raises (Parse)
{
	if(o+4 > len d)
		raise Parse("short buffer");
	v := 0;
	v |= int d[o++]<<24;
	v |= int d[o++]<<16;
	v |= int d[o++]<<8;
	v |= int d[o++]<<0;
	return (v, o);
}

gopaque(buf: array of byte, o: int, max: int): (array of byte, int) raises (Parse)
{
	n: int;
	(n, o) = g32(buf, o);
	if(max >= 0 && n > max)
		raise Parse(sprint("opaque larger than max allowed (%d > %d)", n, max));
	if(o+n > len buf)
		raise Parse(sprint("short buffer, opaque length %d, have %d", n, len buf-o));
	return (buf[o:o+n], o+n);
}

gstr(buf: array of byte, o: int, max: int): (string, int) raises (Parse)
{
	n: int;
	(n, o) = g32(buf, o);
	if(max >= 0 && n > max)
		raise Parse(sprint("string larger than max allowed (%d > %d)", n, max));
	if(o+n > len buf)
		raise Parse(sprint("short buffer, string length %d, have %d", n, len buf-o));
	return (string buf[o:o+n], o+n);
}

say(s: string)
{
	sys->fprint(sys->fildes(2), "%s\n", s);
}
