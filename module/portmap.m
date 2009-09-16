Portmap: module
{
	PATH:	con "/dis/lib/portmap.dis";

	dflag:	int;

	# getport's proto
	Tcp:	con 6;
	Udp:	con 17;

	getport:	fn(tcp: int, host, port: string, prog, version, proto: int): int;
};
