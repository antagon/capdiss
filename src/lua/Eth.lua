Eth = {
	dst = nil,
	src = nil,
	proto = nil
}

function Eth.len ()
	return 6 + 6 + 2
end

function Eth.parse (data)
	Eth.dst = string.format ("%02x:%02x:%02x:%02x:%02x:%02x",
								data:byte (1),
								data:byte (2),
								data:byte (3),
								data:byte (4),
								data:byte (5),
								data:byte (6))
	Eth.src = string.format ("%02x:%02x:%02x:%02x:%02x:%02x",
								data:byte (7),
								data:byte (8),
								data:byte (9),
								data:byte (10),
								data:byte (11),
								data:byte (12))

	-- TODO: load the value and convert it to correct endian
	Eth.proto = 0
end

function Eth.get_proto_by_id (proto_id)
	-- TODO: load the list
end

