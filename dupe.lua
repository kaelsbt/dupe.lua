--[[
====================================================================
  CTSaveCancel — Save Cancel / Rollback Exploit
  Game        : Roblox "Catch and Tame"
  Executor    : Delta (Android / PC) — API UNC standard
  Versi       : 1.0.0
--------------------------------------------------------------------
  APA INI?
  Script riset/edukasi exploit Roblox. Rollback murni client-side:
  MEMBATALKAN penulisan data, BUKAN memutar waktu nyata.

  CARA KERJA
  1. Skrip memasang hook di semua jalur save yang bisa dijangkau client:
     - HttpService (PostAsync / GetAsync / RequestAsync)
     - RemoteEvent / RemoteFunction ber-nama "save"
     - fungsi "save" di environment LocalScript / ModuleScript
  2. Setelah hasil gacha jelek, panggil  _G.CTSaveCancel:arm("alasan")
  3. Semua jalur save diblokir + payload rusak dikirim ke remote save
     agar handler server error SEBELUM sempat menulis ke DataStore.
  4. Skrip memaksa kick/disconnect sebelum autosave berikutnya.
  5. Auto-rejoin ke SERVER BARU -> game membaca DataStore LAMA ->
     mata uang kembali utuh.

  CARA PAKAI (Delta Android)
  1. Buka Roblox -> masuk ke Catch and Tame.
  2. Buka Delta executor -> Inject/Attach.
  3. Paste isi file ini -> Execute.
  4. Periksa console. Pastikan muncul "[CTS] Remote save: ..."
     (artinya jalur save bisa di-intercept). Jika muncul pesan
     "kemungkinan save server-side", trik ini TIDAK akan bekerja.
  5. Main gacha seperti biasa.
  6. Jika hasil jelek, ketik di kolom input executor:
       _G.CTSaveCancel:arm("hasil jelek")
  7. Skrip otomatis: blokir save -> kick -> rejoin ke server baru.
  8. Verifikasi mata uang kembali ke nilai sebelum gacha.

  KONFIGURASI (edit tabel CONFIG di bawah)

  | Opsi              | Default | Fungsi                                  |
  |-------------------|---------|------------------------------------------|
  | BLOCK_HTTP        | true    | Blokir save via HttpService              |
  | BLOCK_REMOTE      | true    | Blokir remote "save" dari client         |
  | CORRUPT_REMOTE    | true    | Kirim payload rusak ke remote save       |
  | HOOK_LOCAL_FUNC   | true    | Sabotase fungsi save di local script     |
  | KICK_ON_ARM       | true    | Kick/disconnect setelah arm              |
  | AUTO_REJOIN       | true    | Rejoin otomatis ke server baru           |
  | KICK_DELAY        | 0.4     | Jeda sebelum kick (detik)                |
  | HOTKEY_ENABLED    | false   | Hotkey arm untuk PC (tombol "P")         |

  KAPAN BEKERJA / TIDAK
  - BEKERJA  : game menyimpan data lewat client — HttpService ke web
    API, remote "save", atau fungsi save di LocalScript/ModuleScript.
  - TIDAK    : game menyimpan murni server-side (DataStore timer di
    ServerScriptService tanpa remote yang bisa di-hook). Tidak ada
    cara client-side untuk mencegah autosave server pada kasus ini.

  PERINGATAN
  Melanggar ToS Roblox dan rules game. Gunakan di akun sendiri,
  sadari risiko ban. Untuk tujuan edukasi/riset.

  LISENSI: MIT
====================================================================
]]

--=========================== SERVICE ================================
local Players           = game:GetService("Players")
local HttpService       = game:GetService("HttpService")
local TeleportService   = game:GetService("TeleportService")
local NetworkClient     = game:GetService("NetworkClient")
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local UserInputService  = game:GetService("UserInputService")

local LP = Players.LocalPlayer

--========================= KONFIGURASI ==============================
local CONFIG = {
    BLOCK_HTTP      = true,  -- blokir save via HttpService (database eksternal)
    BLOCK_REMOTE    = true,  -- blokir remote "save" dari client
    CORRUPT_REMOTE  = true,  -- kirim payload rusak -> server error sebelum menulis
    HOOK_LOCAL_FUNC = true,  -- sabotase fungsi save di LocalScript/ModuleScript
    KICK_ON_ARM     = true,  -- paksa kick/disconnect setelah arm
    AUTO_REJOIN     = true,  -- teleport ke server baru setelah kick
    KICK_DELAY      = 0.4,   -- jeda (detik) sebelum kick, biar blokir nempel
    HOTKEY_ENABLED  = false, -- aktifkan hotkey untuk arm (PC)
    HOTKEY          = "P",
    REMOTE_KEYWORDS = {
        "save", "autosave", "datasync", "syncdata",
        "savefile", "savegame", "write", "persist",
    },
}

--========================= STATE ====================================
local armed, blocked, injecting = false, false, false
local CTS = {}
_G.CTSaveCancel = CTS

--========================= UTIL =====================================
local function matchesKeyword(s)
    s = tostring(s):lower()
    for _, kw in ipairs(CONFIG.REMOTE_KEYWORDS) do
        if s:find(kw, 1, true) then return true end
    end
    return false
end

local function log(...) print("[CTS]", ...) end

--=================== 1) BLOKIR HttpService ==========================
if CONFIG.BLOCK_HTTP then
    local ok1, oldPost = pcall(hookfunction, HttpService.PostAsync,
        newcclosure(function(self, url, data, ...)
            if blocked and matchesKeyword(url) then
                return '{"ok":true,"saved":false}' -- bohongi game: seolah sukses
            end
            return oldPost(self, url, data, ...)
        end))
    if not ok1 then log("Gagal hook PostAsync:", oldPost) end

    local ok2, oldGet = pcall(hookfunction, HttpService.GetAsync,
        newcclosure(function(self, url, ...)
            if blocked and matchesKeyword(url) then return "[]" end
            return oldGet(self, url, ...)
        end))
    if not ok2 then log("Gagal hook GetAsync:", oldGet) end

    local ok3, oldReq = pcall(hookfunction, HttpService.RequestAsync,
        newcclosure(function(self, opts, ...)
            if blocked and matchesKeyword(opts and opts.Url) then
                return { Success = true, StatusCode = 200, Body = '{"ok":true}' }
            end
            return oldReq(self, opts, ...)
        end))
    if not ok3 then log("Gagal hook RequestAsync:", oldReq) end

    log("Hook HttpService terpasang.")
end

--=================== 2) BLOKIR REMOTE SAVE ==========================
local oldNamecall
oldNamecall = hookmetamethod(game, "__namecall", newcclosure(function(self, ...)
    if injecting then return oldNamecall(self, ...) end

    local method = getnamecallmethod()
    if method == "FireServer" or method == "InvokeServer" then
        local nm = tostring(self)
        local isSave = matchesKeyword(nm)

        if isSave then
            if blocked then
                return nil -- remote save dibekukan total
            end
            if CONFIG.CORRUPT_REMOTE and armed and not blocked then
                -- kirim data rusak -> handler server error sebelum menulis
                injecting = true
                pcall(function()
                    local bad = {
                        __cts_corrupt = true,
                        nan  = math.huge - math.huge,
                        obj  = workspace,
                        deep = { { { { 1, 2, 3 } } } },
                    }
                    if method == "FireServer" then
                        self:FireServer(bad)
                    else
                        self:InvokeServer(bad)
                    end
                end)
                injecting = false
                return nil
            end
        end

        -- log remote gacha (konfirmasi trigger yang benar)
        local lnm = nm:lower()
        if lnm:find("gacha") or lnm:find("pull") or lnm:find("hatch")
           or lnm:find("spin") or lnm:find("egg") then
            log("Remote gacha terdeteksi:", nm)
        end
    end
    return oldNamecall(self, ...)
end))
log("Hook namecall terpasang.")

--================ 3) SABOTASE FUNGSI SAVE LOKAL =====================
local function scanForSaves()
    if not CONFIG.HOOK_LOCAL_FUNC then return end

    local function hookEnv(scr)
        local ok, env = pcall(getsenv, scr)
        if not ok then return end
        for k, v in pairs(env) do
            if type(v) == "function" and tostring(k):lower():find("save") then
                local orig = v
                env[k] = newcclosure(function(...)
                    if blocked then error("[CTS] fungsi save diblokir", 2) end
                    return orig(...)
                end)
                log("Hook fungsi save:", scr.Name, "->", tostring(k))
            end
        end
    end

    local function hookModule(mod)
        local ok, t = pcall(require, mod)
        if not ok or type(t) ~= "table" then return end
        for k, v in pairs(t) do
            if type(v) == "function" and tostring(k):lower():find("save") then
                local orig = v
                t[k] = newcclosure(function(...)
                    if blocked then error("[CTS] save module diblokir", 2) end
                    return orig(...)
                end)
                log("Hook module:", mod.Name, "->", tostring(k))
            end
        end
    end

    local function walk(root)
        for _, scr in ipairs(root:GetDescendants()) do
            if scr:IsA("LocalScript") then
                hookEnv(scr)
            elseif scr:IsA("ModuleScript") then
                hookModule(scr)
            end
        end
    end

    walk(LP.PlayerScripts)
    walk(ReplicatedStorage)
end

--================ 4) KORUPSI SEMUA REMOTE SAVE ======================
local function corruptAllSaves()
    local bad = {
        __cts_corrupt = true,
        nan  = math.huge - math.huge,
        obj  = workspace,
        deep = { { { { 1, 2, 3 } } } },
    }
    for _, root in ipairs({ ReplicatedStorage, workspace }) do
        for _, r in ipairs(root:GetDescendants()) do
            if r:IsA("RemoteEvent") and matchesKeyword(r.Name) then
                pcall(function() r:FireServer(bad) end)
            elseif r:IsA("RemoteFunction") and matchesKeyword(r.Name) then
                pcall(function() r:InvokeServer(bad) end)
            end
        end
    end
end

--====================== 5) KICK & REJOIN ============================
local function forceKick()
    local kicked = false
    pcall(function()
        LP:Kick("[CTS] save cancel - kembali dengan data lama")
        kicked = true
    end)
    if not kicked then
        pcall(function() NetworkClient:Disconnect() end)
    end
end

local function rejoinToNewServer()
    pcall(function()
        -- server BARU => DataStore lama yang terbaca
        TeleportService:Teleport(game.PlaceId, LP)
    end)
end

--=================== 6) PUBLIC API ==================================
function CTS:arm(why)
    if armed then
        log("Sudah ARMED. Tidak melakukan apa-apa.")
        return
    end
    armed = true
    log("ARMED - alasan:", why or "hasil gacha jelek")
    task.wait(CONFIG.KICK_DELAY)
    blocked = true
    log("SAVE DIBLOKIR - server tidak akan menulis data baru.")

    if CONFIG.CORRUPT_REMOTE then
        injecting = true
        corruptAllSaves()
        injecting = false
    end

    if CONFIG.KICK_ON_ARM then
        task.wait(CONFIG.KICK_DELAY)
        log("Memaksa kick/disconnect...")
        forceKick()
        if CONFIG.AUTO_REJOIN then
            task.wait(0.3)
            log("Rejoin ke server baru...")
            rejoinToNewServer()
        end
    end
end

function CTS:disarm()
    armed, blocked = false, false
    log("DISARMED - save normal kembali.")
end

function CTS:scan()
    log("Scan jalur save...")
    local found = 0
    for _, root in ipairs({ ReplicatedStorage, workspace }) do
        for _, r in ipairs(root:GetDescendants()) do
            if (r:IsA("RemoteEvent") or r:IsA("RemoteFunction"))
               and matchesKeyword(r.Name) then
                log("Remote save:", r:GetFullName())
                found = found + 1
            end
        end
    end
    if found == 0 then
        log("Tidak ada remote 'save' ditemukan - kemungkinan save server-side.")
        log("Trik ini mungkin TIDAK bekerja untuk game ini.")
    else
        log("Ditemukan", found, "remote save. Trik siap dipakai.")
    end
end

--=========================== 7) INIT ================================
task.wait(2) -- tunggu game & PlayerScripts load

pcall(scanForSaves)
CTS:scan()

if CONFIG.HOTKEY_ENABLED then
    UserInputService.InputBegan:Connect(function(input)
        if input.KeyCode == Enum.KeyCode[CONFIG.HOTKEY] then
            CTS:arm("hotkey " .. CONFIG.HOTKEY)
        end
    end)
end

log("Siap. Main gacha dulu - kalau hasilnya JELEK, ketik di executor:")
log('  _G.CTSaveCancel:arm("hasil jelek")')
log("Batalin eksekusi save-cancel:")
log("  _G.CTSaveCancel:disarm()")
