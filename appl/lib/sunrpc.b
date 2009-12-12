implement Sunrpc;

include "sys.m";
	sys: Sys;
	sprint: import sys;
include "sunrpc.m";

dflag = 0;

init()
{
	sys = load Sys Sys->PATH;
}


writerpc[T](fd: ref Sys->FD, pre: array of byte, wrapmsg: int, m: T): string
	for {
	T =>	size:   fn(m: T): int;
		pack:	fn(m: T, buf: array of byte, o: int): int;
	}
{
	size := m.size(m);
	wrap := 0;
	if(wrapmsg)
		wrap = 4;
	buf := array[len pre+wrap+size] of byte;
	o := 0;
	if(len pre > 0) {
		buf[o:] = pre;
		o += len pre;
	}
	if(wrapmsg)
		o = p32(buf, o, (1<<31)|size);
	o = m.pack(m, buf, o);
	if(o != len buf)
		return "bad pack";
	if(sys->write(fd, buf, len buf) != len buf)
		return sprint("write: %r");
	return nil;
}

readmsg(fd: ref Sys->FD): (array of byte, string)
{
if(dflag)say("reading Trpc");
	buf := array[0] of byte;
	for(;;) {
		sbuf := array[4] of byte;
		if(sys->readn(fd, sbuf, len sbuf) != len sbuf)
			return (nil, "short read");
		v := g32(sbuf, 0).t0;
		end := v&(1<<31);
		v &= ~end;
		if(v > 1024+128*1024) # overhead, plus large nfs read/write
			return (nil, "message too long");
		if(end)
			end = 1;
if(dflag)say(sprint("Trpc, fragment, length %d, end %d", v, end));

		nbuf := array[len buf+v] of byte;
		nbuf[:] = buf;
		if(sys->readn(fd, nbuf[len buf:], v) != v)
			return (nil, "short read");
		buf = nbuf;

		if(end)
			break;
	}
if(dflag)say(sprint("Trpc, have request, length %d", len buf));
	return (buf, nil);
}

parsereq[T](buf: array of byte, m: T): T
	for {
	T =>	unpack: fn(m: ref Trpc, buf: array of byte): T raises (Badrpc, Badprog, Badproc, Badprocargs);
	}
	raises (Parse, Badrpc)
{
	r := ref Trpc;
	nullverf: Auth;
	nullverf.which = Anone;
	{
		o := 0;
		(r.xid, o) = g32(buf, o);
		msgtype: int;
		(msgtype, o) = g32(buf, o);
		if(msgtype != MTcall)
			raise Parse("message rpc response, expected rpc request");
		(r.rpcvers, o) = g32(buf, o);
		if(r.rpcvers != Rpcversion)
			raise Badrpcversion();
		(r.prog, o) = g32(buf, o);
		(r.vers, o) = g32(buf, o);
		(r.proc, o) = g32(buf, o);
		(r.cred.which, o) = g32(buf, o);
		(r.cred.buf, o) = gopaque(buf, o, Authmax);
		(r.verf.which, o) = g32(buf, o);
		(r.verf.buf, o) = gopaque(buf, o, Authmax);
if(dflag)say(sprint("Trpc, prog %d, vers %d, proc %d", r.prog, r.vers, r.proc));
		return m.unpack(r, buf[o:]);
	} exception e {
	Parse =>
		raise;
	Badrpcversion =>
		raise Badrpc (sprint("bad rpc version, %d", r.rpcvers), nil, ref Rrpc.Rpcmismatch (r.xid, 2, 2));

	Badrpc =>
		pick out := e.t2 {
		Progmismatch =>
			out.verf = nullverf;
		}
		raise;
	Badprog =>
		raise Badrpc (sprint("bad program, %d", r.prog), nil, ref Rrpc.Badprog (r.xid, nullverf));
	Badproc =>
		raise Badrpc (sprint("bad procedure, %d", r.proc), nil, ref Rrpc.Badproc (r.xid, nullverf));
	Badprocargs =>
		raise Badrpc (e, nil, ref Rrpc.Badprocargs (r.xid, nullverf));
	}
}

parseresp[T](tm: ref Trpc, buf: array of byte, m: T): T
	for {
	T =>	unpack:	fn(tm: ref Trpc, rm: ref Rrpc, buf: array of byte): T raises (Badrpc, Badproc, Badprocargs);
	}
	raises (Parse, Badrpc)
{
	r: ref Rrpc;
	{
		o := 0;
		xid, rpctype, status, msgtype: int;
		(xid, o) = g32(buf, o);
		(rpctype, o) = g32(buf, o);
		if(rpctype != MTreply)
			raise Parse ("not an rpc reply");
		(status, o) = g32(buf, o);
		case status {
		MSGaccepted =>
			verf: Auth;
			(verf.which, o) = g32(buf, o);
			(verf.buf, o) = gopaque(buf, o, -1);
			(msgtype, o) = g32(buf, o);
			case msgtype {
			ACsuccess =>		r = ref Rrpc.Success (xid, verf);
			ACprogmismatch =>
				r = rr := ref Rrpc.Progmismatch (xid, verf, 0, 0);
				(rr.low, o) = g32(buf, o);
				(rr.high, o) = g32(buf, o);
			ACprogunavail =>	r = ref Rrpc.Badprog (xid, verf);
			ACprocunavail =>	r = ref Rrpc.Badproc (xid, verf);
			ACgarbageargs =>	r = ref Rrpc.Badprocargs (xid, verf);
			ACsystemerr =>		r = ref Rrpc.Systemerr (xid, verf);
			}
		MSGdenied =>
			(msgtype, o) = g32(buf, o);
			case msgtype {
			RSrpcmismatch =>
				r = rr := ref Rrpc.Rpcmismatch;
				rr.xid = xid;
				(rr.low, o) = g32(buf, o);
				(rr.high, o) = g32(buf, o);
			RSautherror =>
				r = rr := ref Rrpc.Autherror;
				rr.xid = xid;
				(rr.error, o) = g32(buf, o);
			* =>
				raise Parse ("bad rpc denied");
			}
		* =>
			raise Parse ("bad rpc reply status");
		}
		if(tagof r != tagof Rrpc.Success)
			raise Badrpc ("rpc failed", tm, r);
		return m.unpack(tm, r, buf[o:]);
	} exception e {
	Parse =>
		raise;
	Badrpc =>
		raise;
	Badproc =>
		raise Badrpc ("bad procedure", nil, nil);
	Badprocargs =>
		raise Badrpc (e, nil, nil);
	}
}


Auth.size(a: self Auth): int
{
	return a.pack(nil, 0);
}

Auth.pack(a: self Auth, buf: array of byte, o: int): int
{
	o = p32(buf, o, a.which);
	o = popaque(buf, o, a.buf);
	return o;
}


Authsys.size(a: self ref Authsys): int
{
	return a.pack(nil, 0);
}

Authsys.pack(a: self ref Authsys, buf: array of byte, o: int): int
{
	if(len a.gids > 16)
		raise "too many gids";
	o = p32(buf, o, a.stamp);
	o = pstr(buf, o, a.machine);
	o = p32(buf, o, a.uid);
	o = p32(buf, o, a.gid);
	o = p32(buf, o, len a.gids);
	for(i := 0; i < len a.gids; i++)
		o = p32(buf, o, a.gids[i]);
	return o;
}

Authsys.unpack(buf: array of byte, o: int): ref Authsys raises (Parse)
{
	{
		a := ref Authsys;
		(a.stamp, o) = g32(buf, o);
		(a.machine, o) = gstr(buf, o, 255);
		(a.uid, o) = g32(buf, o);
		(a.gid, o) = g32(buf, o);
		ngids: int;
		(ngids, o) = g32(buf, o);
		if(ngids > 16)
			raise Parse(sprint("too many gids, %d > 16", ngids));
		a.gids = array[ngids] of int;
		for(i := 0; i < ngids; i++)
			(a.gids[i], o) = g32(buf, o);
		if(o != len buf)
			raise Parse(sprint("leftover data, o %d != len buf %d", o, len buf));
		return a;
	} exception e {
	Parse => raise Parse ("auth_sys: "+e);
	}
}

 
Trpc.size(m: self ref Trpc): int
{
	return m.pack(nil, 0);
}

Trpc.pack(m: self ref Trpc, buf: array of byte, o: int): int
{
	o = p32(buf, o, m.xid);
	o = p32(buf, o, MTcall);
	o = p32(buf, o, m.rpcvers);
	o = p32(buf, o, m.prog);
	o = p32(buf, o, m.vers);
	o = p32(buf, o, m.proc);
	o = m.cred.pack(buf, o);
	o = m.verf.pack(buf, o);
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

pbool(d: array of byte, o: int, v: int): int
{
	if(v)
		v = 1;
	return p32(d, o, v);
}

pboolopaque(d: array of byte, o: int, buf: array of byte): int
{
	o = pbool(d, o, buf!=nil);
	if(buf != nil)
		o = popaque(d, o, buf);
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

p64(d: array of byte, o: int, v: big): int
{
	if(d == nil)
		return o+8;
	d[o++] = byte (v>>56);
	d[o++] = byte (v>>48);
	d[o++] = byte (v>>40);
	d[o++] = byte (v>>32);
	d[o++] = byte (v>>24);
	d[o++] = byte (v>>16);
	d[o++] = byte (v>>8);
	d[o++] = byte (v>>0);
	return o;
}

popaque(d: array of byte, o: int, buf: array of byte): int
{
	if(d == nil)
		return o+4+up4(len buf);
	o = p32(d, o, len buf);
	d[o:] = buf;
	o += len buf;
	o = clearpad(d, o);
	return o;
}

popaquefixed(d: array of byte, o: int, buf: array of byte): int
{
	if(d == nil)
		return o+up4(len buf);
	d[o:] = buf;
	o += len buf;
	o = clearpad(d, o);
	return o;
}


pstr(d: array of byte, o: int, s: string): int
{
	if(d == nil)
		return o+4+up4(len array of byte s);
	buf := array of byte s;
	o = p32(d, o, len buf);
	d[o:] = buf;
	o += len buf;
	o = clearpad(d, o);
	return o;
}

g32(d: array of byte, o: int): (int, int) raises (Parse)
{
	if(o+4 > len d)
		raise Parse(sprint("g32: short buffer, o+4 %d > len d %d", o+4, len d));
	v := 0;
	v |= int d[o++]<<24;
	v |= int d[o++]<<16;
	v |= int d[o++]<<8;
	v |= int d[o++]<<0;
	return (v, o);
}

gbool(d: array of byte, o: int): (int, int) raises (Parse)
{
	if(o+4 > len d)
		raise Parse(sprint("gbool: short buffer, o+4 %d > len d %d", o+4, len d));
	v := 0;
	v |= int d[o++]<<24;
	v |= int d[o++]<<16;
	v |= int d[o++]<<8;
	v |= int d[o++]<<0;
	if(v != 0 && v != 1)
		raise Parse(sprint("gbool: bad value %d, only 0 & 1 allowed", v));
	return (v, o);
}

g64(d: array of byte, o: int): (big, int) raises (Parse)
{
	if(o+8 > len d)
		raise Parse(sprint("g64, short buffer, o+8 %d > len d %d", o+8, len d));
	v := big 0;
	v |= big d[o++]<<56;
	v |= big d[o++]<<48;
	v |= big d[o++]<<40;
	v |= big d[o++]<<32;
	v |= big d[o++]<<24;
	v |= big d[o++]<<16;
	v |= big d[o++]<<8;
	v |= big d[o++]<<0;
	return (v, o);
}

gopaque(buf: array of byte, o: int, max: int): (array of byte, int) raises (Parse)
{
	{
		n: int;
		(n, o) = g32(buf, o);
		if(max >= 0 && n > max)
			raise Parse(sprint("opaque larger than max allowed (%d > %d)", n, max));
		if(o+n > len buf)
			raise Parse(sprint("short buffer, opaque end o+n %d+%d > len buf %d", o, n, len buf));
		return (buf[o:o+n], up4(o+n));
	} exception e {
	Parse => raise Parse("gopaque: "+e);
	}
}

gopaquefixed(buf: array of byte, o: int, n: int): (array of byte, int) raises (Parse)
{
	{
		if(o+n > len buf)
			raise Parse(sprint("short buffer, opaque end o+n %d+%d > len buf %d", o, n, len buf));
		return (buf[o:o+n], up4(o+n));
	} exception e {
	Parse => raise Parse("gopaquefixed: "+e);
	}
}

gstr(buf: array of byte, o: int, max: int): (string, int) raises (Parse)
{
	{
		n: int;
		(n, o) = g32(buf, o);
		if(max >= 0 && n > max)
			raise Parse(sprint("string larger than max allowed (%d > %d)", n, max));
		if(o+n > len buf)
			raise Parse(sprint("short buffer, string end o+n %d+%d > len buf %d", o, n, len buf));
		return (string buf[o:o+n], o+up4(n));
	} exception e {
	Parse => raise Parse("gstr: "+e);
	}
}

clearpad(d: array of byte, o: int): int
{
	n := (4-(o&3))&3;
	d[o:] = array[n] of {* => byte 0};
	return o+n;
}

up4(n: int): int
{
	return (n+3)&~3;
}

say(s: string)
{
	sys->fprint(sys->fildes(2), "%s\n", s);
}
