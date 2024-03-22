---
title: Knight CTF 2022 – Find Pass Code
date: '2022-01-21'
draft: false
authors: ['blueset']
tags: ['Knight CTF 2022', 'PHP', 'Type juggling']
summary: 'Always use === if you can.'
---

## Find Pass Code 1 (50 points)

### Description

> Challenge Link: http://find-pass-code-one.kshackzone.com/  
> Flag Format: `KCTF{something_here}`  
> Note: Burte Force/Fuzzing not required and not allowed.  
> Author: NomanProdhan

Webpage has a form with a text box and a submit button. The form sends a POST request to `/`.

A comment is found in the HTML source of the webpage.

```html
<!-- Hi Serafin, I learned something new today. 
I build this website for you to verify our KnightCTF 2022 pass code. You can view the source code by sending the source param
-->
```

Visiting https://find-pass-code-one.kshackzone.com/?source gives the PHP source code.

```php
<?php
require "flag.php";
if (isset($_POST["pass_code"])) {
    if (strcmp($_POST["pass_code"], $flag) == 0 ) {
        echo "KCTF Flag : {$flag}";
    } else {
        echo "Oh....My....God. You entered the wrong pass code.<br>";
    }
}
if (isset($_GET["source"])) {
    print show_source(__FILE__);
}

?>
```

**Vulnerability:** When comparing non-string values, `strcmp()` returns `null`, which is `== 0` but not `=== 0` in PHP. We need to make `$_POST["pass_code"]` a non-string value.

One way to do this is to supply an array argument in the Post Payload.

```
pass_code[]=value
```

In this way, `$_POST["pass_code"]` will be assigned as `array(0 => "value")`, thus allowing us to bypass the check.

## Find Pass Code 2 (150 points)

> Challenge Link: http://find-pass-code-two.kshackzone.com/  
> Flag Format: `KCTF{something_here}`  
> Note: Burte Force/Fuzzing not required and not allowed.  
> Author: NomanProdhan

Webpage has a form with a text box and a submit button. The form sends a POST request to `/`.

A comment is found in the HTML source of the webpage.

```html
<!-- Hi Serafin, I think you already know how you can view the source code :P
-->
```

Again, visiting https://find-pass-code-two.kshackzone.com/?source gives the PHP source code.

```php
<?php
require "flag.php";
$old_pass_codes = array("0e215962017", "0e730083352", "0e807097110", "0e840922711");
$old_pass_flag = false;
if (isset($_POST["pass_code"]) && !is_array($_POST["pass_code"])) {
    foreach ($old_pass_codes as $old_pass_code) {
        if ($_POST["pass_code"] === $old_pass_code) {
            $old_pass_flag = true;
            break;
        }
    }
    if ($old_pass_flag) {
        echo "Sorry ! It's an old pass code.";
    } else if ($_POST["pass_code"] == md5($_POST["pass_code"])) {
        echo "KCTF Flag : {$flag}";
    } else {
        echo "Oh....My....God. You entered the wrong pass code.<br>";
    }
}
if (isset($_GET["source"])) {
    print show_source(__FILE__);
}

?>
```

**Vulnerability:** When comparing strings using `==`, PHP will try to attempt to parse the string as a number. Hence, strings like `"0e1"` and `"0e2"` will be considered as the value `0` in scientific notation. We need to find a string which both the string itself and its MD5 hash match the pattern `0e[0-9]+`.

`$old_pass_codes` has blacklisted some known strings that have this property.

Searching online, _[PHP Juggling type and magic hashes](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Type%20Juggling/README.md)_ provided another string – `0e1137126905` – that also has this property but not blacklisted. 

Submitting this code, and we can get the flag.
