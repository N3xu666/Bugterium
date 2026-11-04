@{
    # =========================================================================
    # writeup-spec.psd1
    # Single source of truth for HTB walkthrough structure and localization.
    # Consumed by check.ps1. NOT consumed by mask.ps1 (masking is value-based).
    # Internal file: MASTER_WORKFLOW.md 6.5 / 6.8 are generated FROM this spec.
    # =========================================================================

    SchemaVersion = '1.0.0'
    SpecDate      = '2026-10-25'

    # -------------------------------------------------------------------------
    # BASE: applied to every walkthrough, in every language.
    # Overlays below extend or override per machine type.
    # -------------------------------------------------------------------------
    Base = @{
        # Sections that MUST appear (in this order) in every full walkthrough.
        # Order is enforced by check.ps1. Stub files (SeasonStub overlay) relax this.
        RequiredH2 = @(
            'Attack Chain',
            'Machine Briefing',
            'Reconnaissance',
            'Foothold',
            'Exploitation',
            'Privilege Escalation',
            'Flags',
            'Key Takeaways'
        )

        # Optional H2 sections: allowed, not required.
        OptionalH2 = @(
            'Lateral Movement',
            'Authenticated Enumeration',
            'Enumeration',
            'Credential Leak',
            'SSH Access',
            'KeePass Memory Dump',
            'Root',
            'Exploitation'
        )

        # Meta block: exactly these labels, in this order, in the `>` header.
        # Each label maps to its localized form in each language.
        MetaLabels = @{
            En = @('Platform', 'OS', 'Difficulty', 'Result')
            Ru = @('Платформа', 'ОС', 'Сложность', 'Результат')
            Az = @('Platforma', 'OS', 'Çətinlik', 'Nəticə')
        }

        # Platform value: never localized.
        PlatformValue = 'Hack The Box'

        # OS values: never localized.
        OSValues = @('Linux', 'Windows', 'FreeBSD', 'Solaris')

        # Difficulty values: LOCALIZED (the value itself is translated).
        DifficultyValues = @{
            En = @('Easy', 'Medium', 'Hard', 'Insane')
            Ru = @('Легко', 'Средне', 'Сложно', 'Безумно')
            Az = @('Asan', 'Orta', 'Çətin', 'Dəli')
        }

        # Result values: never localized.
        ResultValues = @('user', 'root', 'SYSTEM', 'Administrator')

        # Ethical note text (right after Attack Chain, before the closing `---`).
        EthicalNote = @{
            En = 'All flags, passwords, hashes, and session tokens have been masked for ethical reasons.'
            Ru = 'Все флаги, пароли, хэши и сессионные токены были замаскированы по этическим соображениям.'
            Az = 'Bütün bayraqlar, şifrələr, heşlər və sessiya tokenləri etik səbəblərə görə gizlədilmişdir.'
        }

        # Short-form EthicalNote variants: accepted by check.ps1 [3/23].
        # Exact in-file variants accepted by check.ps1 [3/23].
        # These MUST match the literal text in walkthrough files.
        EthicalNoteShort = @{
            En = 'All flags, passwords, hashes, and session tokens have been masked for ethical reasons.'
            Ru = 'Все флаги, пароли, хеши и токены сессий были замаскированы по этическим соображениям.'
            Az = 'Bütün bayraqlar, şifrələr, heşlər və sessiya tokenləri etik səbəblərə görə gizlədilmişdir.'
        }

        # References etalon rules (WARN only, non-blocking).
        # A-format (allowed): description - https://url
        # B-format (WARN):   [text](https://url)
        # C-format (WARN):   description: https://url
        # Skipped (allowed): [text](./relative) and description without URL.
        ReferencesEtalon = @{
            RelativePrefix = '^\[[^\]]+\]\(\.\.?/'
            BPattern       = '^\[[^\]]+\]\(https?://'
            CPattern       = ':\s+https?://'
        }

        # OSCP marker: ALWAYS English, in all three languages (fixed string).
        OscpMarker = 'OSCP report: take a screenshot of this step (command + output + timestamp).'

        # Placeholders that must never leak a real value.
        Placeholders = @(
            '<USER_FLAG>', '<ROOT_FLAG>', '<SYSTEM_FLAG>',
            '<PASSWORD>', '<BCRYPT_HASH>', '<SHA256_HASH>', '<MYSQL_HASH>',
            '<SECURITY_KEY>', '<TOKEN>', '<SERIAL>', '<BOOKING_REF>',
            '<GPP_CPASSWORD>', '<KRB5TGS_HASH>', '<SESSION_ID>'
        )

        # Flags detection: real HTB flags are 32 lowercase/uppercase hex chars.
        # Matched per-file, outside code blocks (mask.ps1 replaces them, so check
        # should see 0 unless a new one slipped through).
        FlagsRegex = '\b[a-fA-F0-9]{32}\b'

        # Broken characters: U+FFFD replacement character (encoding damage).
        BrokenCharsPattern = '[\uFFFD]'

        # Masking artifacts: placeholder immediately followed by a real suffix
        # (e.g. '<PASSWORD>blog'). Indicates the mask was applied mid-token.
        MaskingArtifacts = @(
            '<PASSWORD>blog',
            '<PASSWORD>.htb',
            '<USER_FLAG>FLAG',
            '<ROOT_FLAG>FLAG'
        )

        # README counter pattern: reads 'Currently: **N published ... + M active stubs** = K completed'.
        # Groups: 1=published, 2=stubs, 3=total.
        ReadmeCounterPattern = 'Currently:\s+\*\*(\d+)\s+published.*?\+\s+(\d+)\s+active stubs\*\*\s+=\s+\*\*(\d+)\s+completed'
        # Long dashes: en dash, em dash, minus sign. check.ps1 [4/23] fails on any.
        LongDashesPattern = '[\u2013\u2014\u2212]'

        # Unreplaced placeholders (%%XX%%) in docs. check.ps1 [9/23] fails.
        UnreplacedPlaceholderPattern = '%%[A-Z0-9]+%%'
        DocRootFiles = @('README.md', 'CHEATSHEET.md', 'METHODOLOGY.md', 'SECURITY.md')

        # Backslash-escaped markdown (from chat/notepad paste). check.ps1 [13/23] fails.
        BackslashEscapePattern = '^\\[#\[\]_()]'
        DocsRoots = @('APPLICATIONS', 'INFRASTRUCTURE', 'ANONYMITY-PRIVACY-OPSEC', 'AI', 'NETWORKS', 'tools')

        # Chat citation markers. check.ps1 [16/23] fails, [23/23] WARNs.
        CitationPattern = 'citation:\d+'

        # Draft-mode scan for active-machine writeups (gitignored txt/).
        DraftPath          = 'txt/active-drafts'
        DraftCitationPattern = '\[citation:\d+\]'
        # Heuristic: suspicious passwords (WARN only).
        # Main regex captures key=value or key: value with value >= 5 chars.
        # Skip patterns discard sudo directives, paths, Hydra placeholders, ALL_CAPS.
        HeuristicRegex = '(?i)(password|passwd|pwd|secret|token|api[_-]?key|apikey)\s*[:=]\s*([^\s<>]{5,})'
        HeuristicSkipPatterns = @(
            '^<.*>$',              # masked placeholder
            '^\[aby]\$',         # bcrypt hash
            '^\*?[A-F0-9]{32,}$',  # long hex hash
            '^[/\\]',              # sudo path / Unix path
            '^\.',                 # relative path
            '\^',                  # Hydra placeholder
            '^[A-Z_]{3,5}$'        # ALL_CAPS identifier
        )
        HeuristicBenignValues = @('password','null','none','undefined','example','test','changeme','N/A')

        # Stale references: old folder names / phrases left after restructure.
        # Any occurrence is a WARN signal. check.ps1 [14/23].
        StaleRefs = @('02 Web', '01 HTB', 'OSCP-grade')

        # Doc-level exclude names (link check [10/23], stale check [14/23]).
        DocExcludeNames = @('ROADMAP.md', 'MASTER_WORKFLOW.md', '_SITE_PLAN.md', 'PROMPT_NEXT_SESSION.txt', 'SESSION_CLOSING_PROTOCOL.md')

        # Language counter marker: U+00D7 MULTIPLICATION SIGN.
        # Written as an escape so this PSD1 stays ASCII-safe (lesson 164).
        TimesSign = [char]0x00D7

        # CVE reference formats accepted inside Exploitation/Foothold.
        CvePattern    = 'CVE-\d{4}-\d{4,}'
        CveNoCveText  = 'No CVE (custom vulnerability)'
        CveLinkHosts  = @('nvd.nist.gov', 'cve.mitre.org')

        # OSCP screenshot notes are optional for retired HTB Season machines.
        # Terminology: fixed localized term pairs. Old = deprecated form (defect),
        # New = correct form. Only Az has a deprecated/current pair today.
        # Built from [char] codes so this file stays ASCII-safe on save.
        Terminology = @{
            Az = @{
                Old = 'Defolt Kredensiallar'
                New = 'Standart Giriş Məlumatları'
            }
        }

        # Character classes used by the English-fragment scan in Az/Ru prose.
        # Cyr: all Cyrillic; Aze: Azerbaijani-only diacritics (no ASCII I, see lesson 155).
        CharClasses = @{
            Cyr = '[А-яЁё]'
            Aze = '[əğıöşüçƏĞÖŞÜÇ]'
        }

        # Whitelist of English technical terms that legitimately stay English in Az/Ru files.
        # The scan skips a line if ANY whitelisted term appears with word boundaries.
        EngWhitelist = @(
            'CVE-','NVD','MITRE','OSCP','Kerberos','LDAP','SMB','RPC','WMI','HTB','Hack The Box',
            'Linux','Windows','FreeBSD','Solaris','Administrator','SYSTEM','root','user',
            'curl','nmap','smbclient','wmiexec','netcat','sudo','powershell','cmd.exe',
            'HTTP','HTTPS','URL','API','JSON','XML','FTP','SSH','DNS','DHCP','TLS','SSL',
            'RSA','AES','SHA','MD5','NTLM','DCSync','Kerberoast','AS-REP','SPN','GPP','cpassword',
            'PRTG','NSClient','Tomcat','WAR','Nadine','IP','TCP','UDP','VM','ISO','OS','CPU','RAM',
            'SQL','XSS','RCE','LFI','RFI','SSRF','IDOR','CSRF','XXE','SSTI','JWT','OAuth','SAML',
            'PKI','X11','IMAP','POP3','SMTP','VPN','ACL','AD','DC','GPO','OU','CN','DN','SAM','LSASS',
            'Mimikatz','Nibbleblog','My Image','arbitrary file upload','MIME validation',
            'DS-Replication','1131f6aa','1131f6ad','89e95b76'
        )
        
        WrongDifficultyRu = @('Средний', 'Легкий', 'Сложный', 'Безумный')

        OscpMarkerRequired = $true
    }

    # -------------------------------------------------------------------------
    # OVERLAYS: per machine type. Merged on top of Base.
    # Only fields that DIFFER from Base need to be listed.
    # -------------------------------------------------------------------------
    Overlays = @{

        # OSCP Linux machines: no extra required section beyond Base.
        Linux = @{
            ExtraRequiredH2 = @()
            Note = 'OSCP Linux: standard Base applies.'
        }

        # OSCP Windows machines: same as Linux (Base covers it).
        Windows = @{
            ExtraRequiredH2 = @()
            Note = 'OSCP Windows: standard Base applies. OSCP markers on foothold/privesc commands.'
        }

        # AD machines: `Authenticated Enumeration` is REQUIRED between Foothold and Exploitation.
        AD = @{
            ExtraRequiredH2 = @('Authenticated Enumeration')
            InsertAfter     = @{ 'Authenticated Enumeration' = 'Foothold' }
            Note = 'Active Directory: Authenticated Enumeration is mandatory between Foothold and Exploitation.'
        }

        # Season stubs for ACTIVE machines: only Attack Chain + Note + meta + status marker.
        SeasonStub = @{
            RequiredH2      = @()   # no full sections required
            ExtraRequiredH2 = @()
            OscpMarkerRequired = $false
            StubMarker     = @{
                En = 'Status: **Completed**'
                Ru = 'Статус: **Завершено**'
                Az = 'Status: **Tamamlandı**'
            }
            Note = 'Active HTB machine: publish neutral stub (NN MachineName.md), keep full writeup in txt/active-drafts/.'
        }
    }
}