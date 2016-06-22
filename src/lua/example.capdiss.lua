--
-- Capdiss script counting frames.
--
capdiss = {}

local i

function capdiss.begin (filename, link_type)
	-- Not much to do here, just initialize the counter variable
	i = 0
	io.write (string.format ("Begin parsing '%s'...\n", filename))
end

function capdiss.each (ts, frame)
	i = i + 1
	io.write (string.format ("%s :: pkt no. %d\n", os.date ("%Y-%m-%d %H:%M:%S", ts), i))
end

function capdiss.finish ()
	io.write (string.format ("Done parsing ... %d\n", i))
end

