allpairs = {}
allnodes = {}

colors = { "red", "green", "blue", "yellow", "magenta", "cyan", "burlywood" }
colornext = 1
colormaps = {}

function getcolor(vlan)
  if(colormaps[vlan]) then
    return colormaps[vlan]
  elseif colors[colornext] then
    colormaps[vlan] = colors[colornext]
    colornext = colornext + 1
    return colormaps[vlan]
  else
    return "black" 
  end
end


function store(key)
  if(not allpairs[key]) then
    allpairs[key] = 1;
  else 
    allpairs[key] = allpairs[key] + 1;
  end
end

function store_node(mac, mcast)
  if(not allnodes[mac]) then
    if mcast then
      allnodes[mac] = "[style=filled, color=green]"
    else
      allnodes[mac] = ""
    end
  end
end

function record(src, smcast, dst, dmcast, vlan)
  local key = "\"" .. src .. "\" -> \"" .. dst .. "\" [color=" .. getcolor(vlan) .. ",label=\"" .. vlan  -- .. "]"
  local key2 = src .. " -> vlan" .. vlan -- .. "[label=" ..dst.."]"
  local key3 = "vlan"..vlan .. " -> " .. dst
  store(key)
  store_node(src, smcast)
  store_node(dst, dmcast)
--  store(key2)
  --store(key3)
end

function printall()
  print ("digraph G {")
  for k,v in pairs(allpairs) do
    print(k .. "(" .. v .. ")\"", "];")
  end
  for k,v in pairs(allnodes) do
    print("\"" .. k .. "\"" .. v .. ";")
  end
  print ("}")
end


