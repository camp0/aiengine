luaunit = require('luaunit')
luaiengine = require('luaiengine')
local inspect = require 'inspect'

TestStackLan = {} 
    function TestStackLan:setUp() 
        self.st = luaiengine.StackLan()
        self.pd = luaiengine.PacketDispatcher()
        --print(inspect(self.st))

        --print(self.st.name)
        -- self.pd:setStack(self.st)
        -- for key,value in pairs(self.pd) do
    end

    function TestStackLan:tearDown() 
    end

    function TestStackLan:testSuperFunction()
        rm = luaiengine.RegexManager()
        r1 = luaiengine.Regex("hola","^jodefr")
        print(inspect(r))
        print("hola")
        rm:add_regex(r1) 
        -- rm:add_regex("hola","^bu bu")
        rm:statistics("hola") 
        -- self.pd:open("eth0")
        luaunit.assertEquals( 3, 3 )
    end

luaunit.LuaUnit:run()
