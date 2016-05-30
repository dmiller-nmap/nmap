---
-- Pack and unpack binary data.
--
-- THIS LIBRARY IS DEPRECATED! Please use builtin Lua 5.3 string.pack facilities.
--
-- A problem script authors often face is the necessity of encoding values
-- into binary data. For example after analyzing a protocol the starting
-- point to write a script could be a hex dump, which serves as a preamble
-- to every sent packet. Although it is possible to work with the
-- functionality Lua provides, it's not very convenient. Therefore NSE includes
-- Binlib, based on lpack (http://www.tecgraf.puc-rio.br/~lhf/ftp/lua/)
-- by Luiz Henrique de Figueiredo.
--
-- The Binlib functions take a format string to encode and decode binary
-- data. Packing and unpacking are controlled by the following operator
-- characters:
-- * <code>H</code> hex string
-- * <code>x</code> null byte
-- * <code>z</code> zero-terminated string
-- * <code>p</code> string preceded by 1-byte integer length
-- * <code>P</code> string preceded by 2-byte integer length
-- * <code>a</code> string preceded by 4-byte integer length
-- * <code>A</code> string
-- * <code>f</code> float
-- * <code>d</code> double
-- * <code>n</code> Lua number
-- * <code>c</code> char (1-byte integer)
-- * <code>C</code> byte = unsigned char (1-byte unsigned integer)
-- * <code>s</code> short (2-byte integer)
-- * <code>S</code> unsigned short (2-byte unsigned integer)
-- * <code>i</code> int (4-byte integer)
-- * <code>I</code> unsigned int (4-byte unsigned integer)
-- * <code>l</code> long (8-byte integer)
-- * <code>L</code> unsigned long (8-byte unsigned integer)
-- * <code><</code> little endian modifier
-- * <code>></code> big endian modifier
-- * <code>=</code> native endian modifier
--
-- Note that the endian operators work as modifiers to all the
-- characters following them in the format string.

local debug2 = require "stdnse".debug2

local assert = assert
local error = error
local ipairs = ipairs
local pcall=pcall
local select=select
local tonumber = tonumber

local char = require "string".char

local insert = require "table".insert
local move = require "table".move
local pack = require "table".pack
local unpack = require "table".unpack

local tobinary = require "stdnse".tobinary

local _ENV = {}

--- Returns a binary packed string.
--
-- The format string describes how the parameters (<code>p1</code>,
-- <code>...</code>) will be interpreted. Numerical values following operators
-- stand for operator repetitions and need an according amount of parameters.
-- Operators expect appropriate parameter types.
--
-- Note: on Windows packing of 64-bit values > 2^63 currently
-- results in packing exactly 2^63.
-- @param format Format string, used to pack following arguments.
-- @param ... The values to pack.
-- @return String containing packed data.
function _ENV.pack (format, ...)
    format = "!1="..format -- 1 byte alignment
    local endianness = "="
    local i, args = 0, pack(...)
    local function translate (o, n)
        if o == "=" or o == "<" or o == ">" then
            endianness = o
            return o
        end
        i = i + 1
        n = #n == 0 and 1 or tonumber(n)
        if o == "H" then
            -- hex string
            -- N.B. n is the reptition
            assert(n > 0, "n cannot be 0") -- original bin library allowed this, it doesn't make sense
            local new = "=" -- !! in original bin library, hex strings are always native
            for j = i, i+n-1 do
                args[j] = args[j]:gsub("(%x%x?)", function (s) return char(tonumber(s, 16)) end)
                new = new .. ("c%d"):format(#args[j])
            end
            new = new .. endianness -- restore old endianness
            return new
        elseif o == "B" then
            -- bit string
            -- N.B. n is the reptition
            error "pack option \"B\" is no longer supported"
        elseif o == "p" then
            return ("s1"):rep(n)
        elseif o == "P" then
            return ("s2"):rep(n)
        elseif o == "a" then
            return ("s4"):rep(n)
        elseif o == "A" then
            -- an unterminated string
            -- N.B. n is the reptition
            assert(n > 0, "n cannot be 0") -- original bin library allowed this, it doesn't make sense
            local new = ""
            for j = i, i+n-1 do
                new = new .. ("c%d"):format(#args[j])
            end
            return new
        elseif o == "c" then
            return ("b"):rep(n)
        elseif o == "C" then
            return ("B"):rep(n)
        elseif o == "s" then
            return ("i2"):rep(n)
        elseif o == "S" then
            return ("I2"):rep(n)
        elseif o == "i" then
            return ("i4"):rep(n)
        elseif o == "I" then
            return ("I4"):rep(n)
        elseif o == "l" then
            return ("i8"):rep(n)
        elseif o == "L" then
            return ("I8"):rep(n)
        else
            return o:rep(n)
        end
    end
    format = format:gsub("([%a=<>])(%d*)", translate)
    return format:pack(unpack(args))
end

do
    -- !! endianness is always big endian for H !!
    assert(_ENV.pack(">H", "415D615A") == "\x41\x5D\x61\x5A")
    assert(_ENV.pack("<H", "415D615A") == "\x41\x5D\x61\x5A")
    assert(_ENV.pack("H2", "415D615A", "A5") == "\x41\x5D\x61\x5A\xA5")

    assert(_ENV.pack("A", "415D615A") == "415D615A")
    --assert(_ENV.pack("A0", "415D615A") == "")
    assert(_ENV.pack("A1", "415D615A", "foo", "bar") == "415D615A")
    assert(_ENV.pack("A2", "415D615A", "foo", "bar") == "415D615Afoo")
end

local function unpacker (fixer, status, ...)
    if not status then return 1 end
    -- Lua's unpack gives the stop index last:
    local list = pack(...)
    for i, v in ipairs(fixer) do
        if v.what == "H" then
            list[v.which] = list[v.which]:gsub(".", function (c) return ("%02X"):format(c:byte()) end)
        elseif v.what == "B" then
            list[v.which] = list[v.which]:gsub(".", function (c) local n = tobinary(c:byte()); return ("0"):rep(8-#n)..n end)
        else
            assert(false)
        end
    end
    return list[list.n], unpack(list, 1, list.n-1)
end

--- Returns values read from the binary packed data string.
--
-- The first return value of this function is the position at which unpacking
-- stopped. This can be used as the <code>init</code> value for subsequent
-- calls. The following return values are the values according to the format
-- string. Numerical values in the format string are interpreted as repetitions
-- like in <code>pack</code>, except if used with <code>A</code>,
-- <code>B</code>, or <code>H</code>, in which cases the number tells
-- <code>unpack</code> how many bytes to read. <code>unpack</code> stops if
-- either the format string or the binary data string are exhausted.
-- @param format Format string, used to unpack values out of data string.
-- @param data String containing packed data.
-- @param init Optional starting position within the string.
-- @return Position in the data string where unpacking stopped.
-- @return All unpacked values.
function _ENV.unpack (format, data, init)
    debug2("format = '%s'", format);
    format = "!1="..format -- 1 byte alignment
    local endianness = "="
    local fixer = {}
    local i = 0
    local function translate (o, n)
        n = #n == 0 and 1 or tonumber(n)
        debug2("%d: %s:%d", i, o, n);

        if o == "=" then
            endianness = "="
            return
        elseif o == "<" then
            endianness = "<"
            return
        elseif o == ">" then
            endianness = ">"
            return
        end

        i = i + 1
        if o == "H" then
            -- hex string
            -- N.B. n is the number of bytes to read
            insert(fixer, {what = "H", which = i})
            return ("=c%d%s"):format(n, endianness) -- !! in original bin library, hex strings are always native endian...
        elseif o == "B" then
            -- bit string
            -- N.B. n is the number of bytes to read
            insert(fixer, {what = "B", which = i})
            return ("=c%d%s"):format(n, endianness) -- !! in original bin library, hex strings are always native endian...
        elseif o == "p" then
            return ("s1"):rep(n)
        elseif o == "P" then
            return ("s2"):rep(n)
        elseif o == "a" then
            return ("s4"):rep(n)
        elseif o == "A" then
            -- an unterminated string
            -- N.B. n is the number of bytes to read
            return ("c%d"):format(n)
        elseif o == "c" then
            return ("b"):rep(n)
        elseif o == "C" then
            return ("B"):rep(n)
        elseif o == "s" then
            return ("i2"):rep(n)
        elseif o == "S" then
            return ("I2"):rep(n)
        elseif o == "i" then
            return ("i4"):rep(n)
        elseif o == "I" then
            return ("I4"):rep(n)
        elseif o == "l" then
            return ("i8"):rep(n)
        elseif o == "L" then
            return ("I8"):rep(n)
        else
            return o:rep(n)
        end
    end
    format = format:gsub("([%a=<>])(%d*)", translate)
    return unpacker(fixer, pcall(format.unpack, format, data, init))
end

do
    local i, v

    -- !! endianness is always native endian for H !!
    i, v = _ENV.unpack("H", "\x00\xff\x0f\xf0")
    assert(i == 2 and v == "00")
    i, v = _ENV.unpack("H0", "\x00\xff\x0f\xf0")
    assert(i == 1 and v == "")
    i, v = _ENV.unpack("H1", "\x00\xff\x0f\xf0")
    assert(i == 2 and v == "00")
    i, v = _ENV.unpack("H2", "\x00\xff\x0f\xf0")
    assert(i == 3 and v == "00FF")
    i, v = _ENV.unpack("<H4", "\x00\xff\x0f\xf0")
    assert(i == 5 and v == "00FF0FF0")
    i, v = _ENV.unpack(">H4", "\x00\xff\x0f\xf0")
    assert(i == 5 and v == "00FF0FF0")

    -- !! endianness is always native endian for B !!
    i, v = _ENV.unpack("B", "\x00\xff\x0f\xf0")
    assert(i == 2 and v == "00000000")
    i, v = _ENV.unpack("B0", "\x00\xff\x0f\xf0")
    assert(i == 1 and v == "")
    i, v = _ENV.unpack("B1", "\x00\xff\x0f\xf0")
    assert(i == 2 and v == "00000000")
    i, v = _ENV.unpack("B2", "\x00\xff\x0f\xf0")
    assert(i == 3 and v == "0000000011111111")
    i, v = _ENV.unpack("<B4", "\x00\xff\x0f\xf0")
    assert(i == 5 and v == "00000000111111110000111111110000")
    i, v = _ENV.unpack(">B4", "\x00\xff\x0f\xf0")
    assert(i == 5 and v == "00000000111111110000111111110000")

    i, v = _ENV.unpack("A", "foo");
    assert(i == 2 and v == "f")
    i, v = _ENV.unpack("A0", "foo");
    assert(i == 1 and v == "")
    i, v = _ENV.unpack("A1", "foo");
    assert(i == 2 and v == "f")
    i, v = _ENV.unpack("A2", "foo");
    assert(i == 3 and v == "fo")
    i, v = _ENV.unpack("A3", "foo");
    assert(i == 4 and v == "foo")
    i, v = _ENV.unpack("A4", "foo");
    assert(i == 1 and v == nil)
end

return _ENV
