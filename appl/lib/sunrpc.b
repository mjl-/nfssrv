implement Sunrpc;

include "sys.m";
	sys: Sys;
	sprint: import sys;
include "sunrpc.m";

init()
{
	sys = load Sys Sys->PATH;
}


rpcwrite(fd: ref Sys->FD, r: ref Rrpc): string
{
	size := r.size();
	buf := array[4+size] of byte;
	o := 0;
	o = p32(buf, o, (1<<31)|size);
	o = r.pack(buf, o);
	if(sys->write(fd, buf, len buf) != len buf)
		return sprint("write: %r");
	return nil;
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
	n := 4+4+4+4;
	pick m := mm {
	Success =>	n += m.verf.size();
	Progmismatch =>	n += m.verf.size()+4+4;
	Badprog or
	Badproc or
	Badprocargs or
	Systemerr =>	n += m.verf.size();
	Rpcmismatch =>	n += 4+4;
	Autherror =>	n += 4;
	* =>	raise "internal error";
	}
	return n;
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
	d[o++] = byte (v>>24);
	d[o++] = byte (v>>16);
	d[o++] = byte (v>>8);
	d[o++] = byte (v>>0);
	return o;
}

popaque(d: array of byte, o: int, buf: array of byte): int
{
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
