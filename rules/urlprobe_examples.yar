/*
    UrlProbe example YARA rules (written for this project, GPL-3.0 like the rest of the repository).
    They show the format and catch a few very common malspam techniques; they are not a complete
    ruleset. Add your own .yar/.yara files to this folder and rebuild the mailbox image
    (docker compose build mailbox) to use them.
*/

rule UrlProbe_EICAR_Test_File
{
    meta:
        description = "EICAR antivirus test string (safe test file)"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule UrlProbe_VBA_AutoExec_Shell
{
    meta:
        description = "VBA macro that runs on open and starts a process or downloads a file"
    strings:
        $auto1 = "AutoOpen" nocase
        $auto2 = "Document_Open" nocase
        $auto3 = "Workbook_Open" nocase
        $auto4 = "Auto_Open" nocase
        $exec1 = "WScript.Shell" nocase
        $exec2 = "Shell(" nocase
        $exec3 = "powershell" nocase
        $exec4 = "URLDownloadToFile" nocase
        $exec5 = "MSXML2.XMLHTTP" nocase
    condition:
        any of ($auto*) and any of ($exec*)
}

rule UrlProbe_PowerShell_Encoded_Command
{
    meta:
        description = "PowerShell started with an encoded (base64) command line"
    strings:
        $ps = "powershell" nocase ascii wide
        $enc = /\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+\/=]{40,}/ nocase ascii wide
    condition:
        $ps and $enc
}

rule UrlProbe_HTML_Smuggling
{
    meta:
        description = "HTML/JS that rebuilds a file in the browser and saves it (HTML smuggling)"
    strings:
        $b64 = "atob(" nocase
        $blob = "new Blob(" nocase
        $url = "createObjectURL" nocase
        $save = "msSaveOrOpenBlob" nocase
        $dl = ".download" nocase
    condition:
        filesize < 20MB and $blob and ($b64 or $url) and ($save or $dl)
}

rule UrlProbe_Telegram_Exfiltration
{
    meta:
        description = "Page or script that sends data to a Telegram bot (common in phishing kits)"
    strings:
        $tg = "api.telegram.org/bot" nocase ascii wide
    condition:
        $tg
}

rule UrlProbe_LNK_LOLBin
{
    meta:
        description = "Windows shortcut that launches a scripting host or downloader"
    strings:
        $lnk = { 4C 00 00 00 01 14 02 00 }
        $t1 = "powershell" nocase ascii wide
        $t2 = "mshta" nocase ascii wide
        $t3 = "cmd.exe" nocase ascii wide
        $t4 = "wscript" nocase ascii wide
        $t5 = "rundll32" nocase ascii wide
        $t6 = "curl" nocase ascii wide
    condition:
        $lnk at 0 and any of ($t*)
}

rule UrlProbe_PE_Inside_Document
{
    meta:
        description = "A Windows executable header embedded inside a document or archive (not at offset 0)"
    strings:
        $mz = "This program cannot be run in DOS mode"
    condition:
        uint16(0) != 0x5A4D and $mz
}
