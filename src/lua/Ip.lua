Ip = {
	tos = nil,
	tot_len = nil,
	id = nil, 
	frag_off = nil,
	ttl = nil,
	protocol = nil,
	check = nil,
	saddr = nil,
	daddr = nil
}

function Ip.len ()
	return 2 + 2 + 2 + 2 + 1 + 1 + 1 + 4 + 4
end

function Ip.parse (data)
	Ip.tos = data:sub (1, 3)
	Ip.tot_len = data:sub (3, 5)
	Ip.id = data:sub (5, 7)
	Ip.frag_off = data:sub (7, 9)
	Ip.ttl = data:sub (9, 10)
	Ip.protocol = data:sub (10, 11)
	Ip.check = data:sub (11, 12)
	Ip.saddr = data:sub (12, 16)
	Ip.daddr = data:sub (16, 20)
end

