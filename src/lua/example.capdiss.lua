--
-- Simple capdiss script.
--
Capdiss = {}

local i = 0

function Capdiss.begin ()
	print ("Begin parsing...")
end

function Capdiss.each (ts, frame)
	i = i + 1

	print (ts .. " :: pkt no. " .. i)
end

function Capdiss.finish ()
	print ("Done parsing ... " .. i .. " packets processed.")
end


