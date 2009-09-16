implement Portmaprpc;

include "sys.m";
	sys: Sys;
	sprint: import sys;
include "sunrpc.m";
	sunrpc: Sunrpc;
	g32, gopaque, gstr, p32, popaque, pstr: import sunrpc;
	Parse, Badprog, Badproc, Badprocargs, Badrpc: import sunrpc;
	Trpc, Rrpc, Auth: import sunrpc;
include "portmaprpc.m";

dflag = 0;

portmaptags = array[] of {
"null", "set", "unset", "getport", "dump", "callit",
};

init()
{
	sys = load Sys Sys->PATH;
	sunrpc = load Sunrpc Sunrpc->PATH;
	sunrpc->init();
}

Tportmap.size(m: self ref Tportmap): int
{
	return m.pack(nil, 0);
}

Tportmap.pack(mm: self ref Tportmap, buf: array of byte, o: int): int
{
	o = mm.r.pack(buf, o);
	pick m := mm {
	Null =>
		;
	Set or
	Unset or
	Getport =>
		o = p32(buf, o, m.map.prog);
		o = p32(buf, o, m.map.vers);
		o = p32(buf, o, m.map.prot);
		o = p32(buf, o, m.map.port);
	Dump =>
		;
	Callit =>
		o = p32(buf, o, m.prog);
		o = p32(buf, o, m.vers);
		o = p32(buf, o, m.proc);
		o = p32(buf, o, m.proc);
		o = popaque(buf, o, m.args);
	}
	return o;
}

Tportmap.unpack(m: ref Trpc, buf: array of byte): ref Tportmap raises (Badrpc, Badprog, Badproc, Badprocargs)
{
	if(m.prog != ProgPortmap)
		raise Badprog;
	if(m.vers != VersPortmap) {
		nullverf: Auth;  # is corrected by caller
		raise Badrpc (sprint("bad version %d", m.vers), nil, ref Rrpc.Progmismatch (m.xid, nullverf, VersPortmap, VersPortmap));
	}

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
			tt = ref Tportmap.Dump (m);
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
			raise Badprocargs(sprint("leftover bytes, o %d < len buf %d", o, len buf));
		return tt;
	} exception e {
	Parse =>
		raise Badprocargs(e);
	Badproc =>
		raise;
	Badprocargs =>
		raise;
	}
}

Rportmap.size(mm: self ref Rportmap): int
{
	return mm.pack(nil, 0);
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
			o = p32(buf, o, 1);
			o = p32(buf, o, m.maps[i].prog);
			o = p32(buf, o, m.maps[i].vers);
			o = p32(buf, o, m.maps[i].prot);
			o = p32(buf, o, m.maps[i].port);
		}
		o = p32(buf, o, 0);
	Callit =>
		o = p32(buf, o, m.port);
		o = popaque(buf, o, m.res);
	* =>	raise "internal error";
	}
	return o;
}

Rportmap.unpack(t: ref Trpc, rm: ref Rrpc, buf: array of byte): ref Rportmap raises (Badrpc, Badproc, Badprocargs)
{
	r: ref Rportmap;
	o := 0;
	case t.proc {
	Mnull =>
		r = ref Rportmap.Null (rm);
	Mset =>
		r = rr := ref Rportmap.Set;
		rr.r = rm;
		(rr.bool, o) = g32(buf, o);
	Munset =>
		r = rr := ref Rportmap.Unset;
		rr.r = rm;
		(rr.bool, o) = g32(buf, o);
	Mgetport =>
		r = rr := ref Rportmap.Getport;
		rr.r = rm;
		(rr.port, o) = g32(buf, o);
	Mdump =>
		r = rr := ref Rportmap.Dump;
		rr.r = rm;
		l: list of Map;
		for(;;) {
			more: int;
			(more, o) = g32(buf, o);
			if(more == 0)
				break;
			m: Map;
			(m.prog, o) = g32(buf, o);
			(m.vers, o) = g32(buf, o);
			(m.prot, o) = g32(buf, o);
			(m.port, o) = g32(buf, o);
			l = m::l;
		}
		m := array[len l] of Map;
		i := len m-1;
		for(; l != nil; l = tl l)
			m[i--] = hd l;
		rr.maps = m;
	Mcallit =>
		r = rr := ref Rportmap.Callit;
		rr.r = rm;
		(rr.port, o) = g32(buf, o);
		(rr.res, o) = gopaque(buf, o, -1); # xxx find real limit
	* =>
		raise Badproc;
	}
	if(o != len buf)
		raise Badprocargs(sprint("leftover bytes, o %d < len buf %d", o, len buf));
	return r;
}
