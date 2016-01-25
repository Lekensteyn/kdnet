-- KD over UDP network dissector
-- Run with: tshark -X lua_script:kdnet.lua

kdnet_proto = Proto("kdnet", "Windows Kernel Debugger over Network")

local hf = {}
function add_field(proto_field_constructor, name, ...)
    local field_name = "kdnet." .. name
    hf[name] = proto_field_constructor(field_name, ...)
end

-- KD serial protocol?
-- http://articles.sysprogs.org/kdvmware/kdcom.shtml
-- http://gr8os.googlecode.com/svn-history/r66/branches/0.2-devel/kernel/kd.cpp
-- http://www.developerfusion.com/article/84367/kernel-and-remote-debuggers/
-- add_field(ProtoField.string, "leader",  "Packet Leader")
-- add_field(ProtoField.uint16, "type",    "Packet Type", base.HEX_DEC)
-- add_field(ProtoField.uint16, "count",   "Byte Count", base.HEX_DEC)
-- add_field(ProtoField.uint32, "id",      "Packet Id", base.HEX_DEC)
-- add_field(ProtoField.uint32, "checksum", "Checksum", base.HEX)

-- KDNET
-- https://github.com/JumpCallPop/libKDNET
add_field(ProtoField.string, "magic",   "Magic")
add_field(ProtoField.uint8, "version",  "Protocol Version", base.HEX)
--[[Found these values for type (count, value for type field, ip.src):
     69 0x00000001      192.168.2.72
  57838 0x00000000      192.168.2.1
  57843 0x00000000      192.168.2.72
Full, smaller run (windbg-uncut):
    262 0x00000000      192.168.2.1
    265 0x00000000      192.168.2.72
    427 0x00000001      192.168.2.72
--]]--
add_field(ProtoField.uint8, "type",     "Type", base.HEX)
add_field(ProtoField.bytes, "data",     "Encrypted data")
add_field(ProtoField.bytes, "data_dec", "Decrypted data")
kdnet_proto.fields = hf

kdnet_proto.prefs.key = Pref.string("Decryption key", "",
    "A 256-bit decryption key formatted as w.x.y.z (components are in base-36)")

-----
-- Decryption routine (based on lua-lockbox, don't worry about timing attacks as
-- the data is not considered confidential.)
-- TODO replace by something faster...
-----
-- For other locations, use: LUA_PATH=.../lua-lockbox/?.lua
package.path = package.path .. ";/home/peter/projects/kdnet/lua-lockbox/?.lua"
package.path = package.path .. ";lua-lockbox/?.lua"
local Lockbox = require("lockbox");
Lockbox.ALLOW_INSECURE = true;
local Array = require("lockbox.util.array");
local CBCMode = require("lockbox.cipher.mode.cbc");
local AES256Cipher = require("lockbox.cipher.aes256");
local ZeroPadding = require("lockbox.padding.zero");
local Stream = require("lockbox.util.stream");
function decrypt(key, data)
    local iv = string.sub(data, -16)
    local ciphertext = string.sub(data, 1, -17)
    local cipher = CBCMode.Decipher()
        .setKey(Array.fromString(key))
        .setBlockCipher(AES256Cipher)
        .setPadding(ZeroPadding);
    local decrypted_bytes = cipher
        .init()
        .update(Stream.fromString(iv))
        .update(Stream.fromString(ciphertext))
        .finish()
        .asBytes();
    return Array.toString(decrypted_bytes)
end
-----
-- Key preparation
-----
function dotted_key(s)
    local key = '';
    for p in string.gmatch(s, "[0-9a-z]+") do
        local n = tonumber(p, 36);
        assert(n < 2^64, "Invalid key")
        local part = '';
        while n > 0 do
            part = string.char(n % 0x100) .. part;
            n = math.floor(n / 0x100);
        end
        key = key .. part .. string.rep('\0', 8 - string.len(part))
    end
    assert(string.len(key) == 32, "Invalid key format")
    return key
end
----

function kdnet_proto.dissector(tvb, pinfo, tree)
    -- Ignore packets not starting with "MDBG"
    if tvb(0, 4):uint() ~= 0x4d444247 then
        return 0
    end
    local decryption_key;
    if kdnet_proto.prefs.key ~= "" then
        decryption_key = dotted_key(kdnet_proto.prefs.key);
    end

    pinfo.cols.protocol = "KDNET"
    local subtree = tree:add(kdnet_proto, tvb())
    subtree:add(hf.magic, tvb(0, 4))
    subtree:add(hf.version, tvb(4, 1))
    subtree:add(hf.type, tvb(5, 1))
    subtree:add(hf.data, tvb(6))
    if decryption_key then
        local enc_data = tvb:raw(6)
        local decrypted_bytes = decrypt(decryption_key, enc_data)
        local dec_data = ByteArray.new(decrypted_bytes, true)
            :tvb("Decrypted KDNET data")
        subtree:add(hf.data_dec, dec_data())
    end

    -- pinfo.cols.protocol = "KD"
    -- subtree:add(hf.leader, tvb(0, 4))
    -- subtree:add(hf.type, tvb(4, 2))
    -- subtree:add(hf.count, tvb(6, 2))
    -- subtree:add(hf.id, tvb(8, 4))
    -- subtree:add(hf.checksum, tvb(12, 4))
    return tvb:len()
end

local udp_table = DissectorTable.get("udp.port")
--udp_table:add(51111, kdnet_proto)
kdnet_proto:register_heuristic("udp", kdnet_proto.dissector)

-- vim: set sw=4 ts=4 et:
