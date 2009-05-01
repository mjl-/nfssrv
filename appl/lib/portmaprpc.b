implement Portmaprpc;

include "sys.m";
include "sunrpc.m";
	sunrpc: Sunrpc;
	g32, gopaque, gstr, p32, popaque, pstr: import sunrpc;
	Parse, Badprog, Badproc, Badprocargs, Badrpc: import sunrpc;
	Trpc, Rrpc, Auth: import sunrpc;
include "portmaprpc.m";

Mnull, Mset, Munset, Mgetport, Mdump, Mcallit: con iota;

init()
{
	sunrpc = load Sunrpc Sunrpc->PATH;
	sunrpc->init();
}

Tportmap.unpack(m: ref Trpc, buf: array of byte): ref Tportmap raises (Badrpc, Badprog, Badproc, Badprocargs)
{
	if(m.prog != ProgPortmap)
		raise Badprog;
	if(m.vers != VersPortmap) {
		nullverf: Auth;  # is corrected by caller
		raise Badrpc (nil, ref Rrpc.Progmismatch (m.xid, nullverf, VersPortmap, VersPortmap));
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
