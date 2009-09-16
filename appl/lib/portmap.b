implement Portmap;

include "sys.m";
	sys: Sys;
	sprint: import sys;
include "sunrpc.m";
	sunrpc: Sunrpc;
	Parse, Badrpc, Badprog, Badproc, Badprocargs: import sunrpc;
include "../lib/portmaprpc.m";
	portmaprpc: Portmaprpc;
	Tportmap, Rportmap, Map: import portmaprpc;
include "util0.m";
	util: Util0;
	l2a, warn, fail, hex, unhex: import util;
include "portmap.m";


dflag = 0;

init()
{
	sys = load Sys Sys->PATH;
	sunrpc = load Sunrpc Sunrpc->PATH;
	sunrpc->init();
	portmaprpc = load Portmaprpc Portmaprpc->PATH;
	portmaprpc->init();
	util = load Util0 Util0->PATH;
	util->init();
}


getport(tcp: int, host, port: string, prog, version, proto: int): int
{
	if(sys == nil)
		init();

	tr := ref Sunrpc->Trpc (sys->millisec(), Sunrpc->Rpcversion, Portmaprpc->ProgPortmap, Portmaprpc->VersPortmap, tagof Tportmap.Getport, Sunrpc->Auth(Sunrpc->Anone, nil), Sunrpc->Auth(Sunrpc->Anone, nil));
	map := Map (prog, version, proto, 0);
	tm := ref Tportmap.Getport (tr, map);

	addr: string;
	if(port == nil)
		port = "sunrpc";
	if(tcp)
		addr = sprint("tcp!%s!%s", host, port);
	else
		addr = sprint("udp!%s!%s", host, port);

	(ok, conn) := sys->dial(addr, nil);
	if(ok != 0)
		return -1;
	fd := conn.dfd;

	if(dflag)
		warn("-> "+portmaprpc->portmaptags[tagof tm]);
	err := sunrpc->writerpc(fd, nil, tcp, tm);
	if(err != nil)
		return error("writing rpc: "+err);

	buf: array of byte;
	if(tcp) {
		(buf, err) = sunrpc->readmsg(fd);
	} else {
		n := sys->read(fd, buf = array[64*1024] of byte, len buf);
		if(n < 0)
			err = sprint("read: %r");
		else
			buf = buf[:n];
	}
	if(err != nil)
		return error("reading rpc: "+err);

	{
		rm: ref Rportmap;
		rm = sunrpc->parseresp(tr, buf, rm);
		if(dflag)
			warn("<- "+portmaprpc->portmaptags[tagof rm]);
		if(rm.r.xid != tm.r.xid)
			return error(sprint("xid mismatch, sent %d, got %d", rm.r.xid, tm.r.xid));
		pick m := rm {
		Getport =>
			if(m.port <= 0)
				sys->werrstr("no such service");
			return m.port;
		* =>
			return error(sprint("proc mismatch, sent 'getport', got %#q", portmaprpc->portmaptags[tagof rm]));
		}
	} exception e {
	Badrpc =>	return error("response: "+e.t0);
	Badproc =>	return error("response: bad proc");
	Badprocargs =>	return error("response: bad procargs");
	}
}

error(s: string): int
{
	sys->werrstr(s);
	return -1;
}
