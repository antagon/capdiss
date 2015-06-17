--
-- Simple capdiss script.
--
Capdiss = {}

i = 0

function Capdiss.begin ()
	print ("Begin parsing...")
end

function Capdiss.each (frame)
	i = i + 1

	print ("Pkt no. " .. i)
end

function Capdiss.finish ()
	print ("Done parsing ... " .. i .. " packets processed.")
end


