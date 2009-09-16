implement Testportmap;

include "sys.m";
	sys: Sys;
	print, sprint: import sys;
include "draw.m";
include "arg.m";
include "sunrpc.m";
	sunrpc: Sunrpc;
	Parse, Badrpc, Badprog, Badproc, Badprocargs: import sunrpc;
include "../lib/portmaprpc.m";
	portmaprpc: Portmaprpc;
	Tportmap, Rportmap, Map: import portmaprpc;
include "util0.m";
	util: Util0;
	l2a, warn, fail, hex, unhex: import util;

Testportmap: module {
	init:	fn(nil: ref Draw->Context, nil: list of string);
};


dflag: int;
tflag: int;

init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	arg := load Arg Arg->PATH;
	sunrpc = load Sunrpc Sunrpc->PATH;
	sunrpc->init();
	portmaprpc = load Portmaprpc Portmaprpc->PATH;
	portmaprpc->init();
	util = load Util0 Util0->PATH;
	util->init();

	arg->init(args);
	arg->setusage(arg->progname()+" [-dt] host [null | [set|unset|getport] prog vers prot port | dump | callit prog vers proc args]");
	while((c := arg->opt()) != 0)
		case c {
		'd' =>	dflag++;
		't' =>	tflag++;
		* =>	arg->usage();
		}
	args = arg->argv();
	if(len args < 2)
		arg->usage();
	host := hd args;
	op := hd tl args;
	t := l2a(tl tl args);
	tr := ref Sunrpc->Trpc (sys->millisec(), Sunrpc->Rpcversion, Portmaprpc->ProgPortmap, Portmaprpc->VersPortmap, -1, Sunrpc->Auth(Sunrpc->Anone, nil), Sunrpc->Auth(Sunrpc->Anone, nil));
	tm: ref Tportmap;
	case op {
	"null" =>
		tm = ref Tportmap.Null (tr);
	"set" or
	"unset" or
	"getport" =>
		if(len t != 4)
			arg->usage();
		m := Map(int t[0], int t[1], int t[2], int t[3]);
		case op {
		"set" =>	tm = ref Tportmap.Set (tr, m);
		"unset" =>	tm = ref Tportmap.Unset (tr, m);
		"getport" =>	tm = ref Tportmap.Getport (tr, m);
		}
	"dump" =>
		tm = ref Tportmap.Dump (tr);
	"callit" =>
		tm = ref Tportmap.Callit (tr, int t[0], int t[1], int t[2], unhex(t[3]));
	* =>
		arg->usage();
	}
	tr.proc = tagof tm;

	addr := sprint("udp!%s!sunrpc", host);
	if(tflag)
		addr = sprint("tcp!%s!sunrpc", host);
	(ok, conn) := sys->dial(addr, nil);
	if(ok != 0)
		fail(sprint("dial: %r"));
	fd := conn.dfd;

	if(dflag)
		warn("-> "+portmaprpc->portmaptags[tagof tm]);
	err := sunrpc->writerpc(fd, nil, tflag, tm);
	if(err != nil)
		fail("writing rpc: "+err);
	buf: array of byte;
	if(tflag) {
		(buf, err) = sunrpc->readmsg(fd);
	} else {
		n := sys->read(fd, buf = array[64*1024] of byte, len buf);
		if(n < 0)
			err = sprint("read: %r");
		else
			buf = buf[:n];
	}
	if(err != nil)
		fail("reading rpc: "+err);
	{
		rm: ref Rportmap;
		rm = sunrpc->parseresp(tr, buf, rm);
		if(dflag)
			warn("<- "+portmaprpc->portmaptags[tagof rm]);
		if(rm.r.xid != tm.r.xid)
			fail(sprint("xid mismatch, sent %d, got %d", rm.r.xid, tm.r.xid));
		if(tagof rm != tagof tm)
			fail(sprint("proc mismatch, sent %d, got %d", tagof tm, tagof rm));
		
		pick m := rm {
		Null =>	;
		Set or
		Unset =>
			print("bool %d\n", m.bool);
		Getport =>
			print("port %d\n", m.port);
		Dump =>
			for(i := 0; i < len m.maps; i++) {
				map := m.maps[i];
				print("map:\n");
				print("\tprog %d\n", map.prog);
				print("\tvers %d\n", map.vers);
				print("\tprot %d\n", map.prot);
				print("\tport %d\n", map.port);
			}
		Callit =>
			print("port %d\n", m.port);
			print("res %s\n", hex(m.res));
		* =>
			raise "missing case";
		}
	} exception e {
	Badrpc =>	fail("response: "+e.t0);
	Badproc =>	fail("response: bad proc");
	Badprocargs =>	fail("response: bad procargs");
	}
}
