--
-- Capdiss script counting frames.
--
Capdiss = {}

local i

function Capdiss.begin ()
	-- Not much to do here, just initialize the counter variable
	i = 0
	print ("Begin parsing...")
end

function Capdiss.each (ts, frame)
	i = i + 1

	print (ts .. " :: pkt no. " .. i)
end

function Capdiss.finish ()
	print ("Done parsing ... " .. i .. " packets processed.")
end

