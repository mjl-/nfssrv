implement Portmap;

include "sys.m";
	sys: Sys;
	sprint: import sys;
include "sunrpc.m";
	sunrpc: Sunrpc;
	g32, gopaque, p32, popaque: import sunrpc;
	IO, Parse, Badrpcversion, Badprog, Badprogversion, Badproc, Badprocargs: import sunrpc;
	Trpc, Rrpc, Auth: import sunrpc;
include "portmap.m";


init()
{
	sys = load Sys Sys->PATH;
	sunrpc = load Sunrpc Sunrpc->PATH;
	sunrpc->init();
}

Tportmap.unpack(m: ref Trpc, buf: array of byte): ref Tportmap raises (Badprog, Badprogversion, Badproc, Badprocargs)
{
	if(m.prog != ProgPortmap)
		raise Badprog;
	if(m.vers != 2)
		raise Badprogversion;

	{
		tt: ref Tportmap;
		o := 0;
		case m.proc {
		Mnull =>
			tt = ref Tportmap.Null (m);
		Mset or
		Munset or
		Mgetport =>
			map: Map;
			(map.prog, o) = g32(buf, o);
			(map.vers, o) = g32(buf, o);
			(map.prot, o) = g32(buf, o);
			(map.port, o) = g32(buf, o);
			case m.proc {
			Mset =>		tt = ref Tportmap.Set (m, map);
			Munset =>	tt = ref Tportmap.Unset (m, map);
			Mgetport =>	tt = ref Tportmap.Getport (m, map);
			}
		Mdump =>
			;
		Mcallit =>
			tt = t := ref Tportmap.Callit;
			t.r = m;
			(t.prog, o) = g32(buf, o);
			(t.vers, o) = g32(buf, o);
			(t.proc, o) = g32(buf, o);
			(t.args, o) = gopaque(buf, o, -1);
		* =>
			raise Badproc;
		}
		if(o != len buf)
			raise Badprocargs;
		return tt;
	} exception {
	Parse =>
		raise Badprocargs();
	Badproc =>
		raise;
	Badprocargs =>
		raise;
	}
}

Rportmap.size(mm: self ref Rportmap): int
{
	n := mm.r.size();
	pick m := mm {
	Null =>	;
	Set or
	Unset =>	n += 4;
	Getport =>	n += 4;
	Dump =>		n += len m.maps*(4*4);
	Callit =>	n += 4+4+len m.res;
	* =>	raise "internal error";
	}
	return n;
}

Rportmap.pack(mm: self ref Rportmap, buf: array of byte, o: int): int
{
	o = mm.r.pack(buf, o);
	pick m := mm {
	Null =>	;
	Set or
	Unset =>
		o = p32(buf, o, m.bool);
	Getport =>
		o = p32(buf, o, m.port);
	Dump =>
		for(i := 0; i < len m.maps; i++) {
			o = p32(buf, o, m.maps[i].prog);
			o = p32(buf, o, m.maps[i].vers);
			o = p32(buf, o, m.maps[i].prot);
			o = p32(buf, o, m.maps[i].port);
		}
	Callit =>
		o = p32(buf, o, m.port);
		o = popaque(buf, o, m.res);
	* =>	raise "internal error";
	}
	return o;
}


trpcread(fd: ref Sys->FD): (ref Trpc, array of byte) raises (IO, Parse, Badrpcversion)
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

	{
		o := 0;
		r := ref Trpc;
		(r.xid, o) = g32(buf, o);
		msgtype: int;
		(msgtype, o) = g32(buf, o);
		if(msgtype != sunrpc->MTcall)
			raise Parse("message rpc response, expected rpc request");
		(r.rpcvers, o) = g32(buf, o);
		if(r.rpcvers != 2)
			raise Badrpcversion();
		(r.prog, o) = g32(buf, o);
		(r.vers, o) = g32(buf, o);
		(r.proc, o) = g32(buf, o);
		(r.cred.which, o) = g32(buf, o);
		(r.cred.buf, o) = gopaque(buf, o, sunrpc->Authmax);
		(r.verf.which, o) = g32(buf, o);
		(r.verf.buf, o) = gopaque(buf, o, sunrpc->Authmax);
		return (r, buf[o:]);
	} exception {
	Parse =>
		raise;
	}
}

portmapread(fd: ref Sys->FD): ref Tportmap raises (IO, Parse, Badrpcversion, Badprog, Badprogversion, Badproc, Badprocargs)
{
	{
		(mrpc, buf) := trpcread(fd);
		return Tportmap.unpack(mrpc, buf);
	} exception {
	IO or
	Parse or
	Badrpcversion or
	Badprog or
	Badprogversion or
	Badproc or
	Badprocargs =>
		raise;
	}
}

portmapwrite(fd: ref Sys->FD, r: ref Rportmap): string
{
	size := r.size();
	buf := array[4+size] of byte;
	o := 0;
	o = p32(buf, o, (1<<31)|size);
	o = r.pack(buf, o);
	if(sys->write(fd, buf, len buf) != len buf)
		return sprint("write: %r");
say(sprint("write portmap reponse, %d bytes", len buf));
say("dump");
say(hex(buf));
	return nil;
}

hex(d: array of byte): string
{
	s := "";
	for(i := 0; i < len d; i++)
		s += sprint("%02x", int d[i]);
	return s;
}

say(s: string)
{
	sys->fprint(sys->fildes(2), "%s\n", s);
}
