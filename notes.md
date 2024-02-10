# EXIM Mail Server

## Vulnerability History

The following is a list of major CVEs in EXIM since 2017. 

* CVE-2017-16943: Use-after-free RCE with RIP-controlling POC is [given](https://bugs.exim.org/show_bug.cgi?id=2199). 
  * Reported 2017-11-23 by meh@devco.re. 
  * Vulnerability (according to report) is in git master at revision 01c594601670c7e48e676d6c6d32d0f0084067fa. 
  * The initial test was on 4.89. 
  * There is an RIP-controllable POC, an updated POC, and the Makefile is given. More detailed writeup from [devco.re](https://devco.re/blog/2017/12/11/Exim-RCE-advisory-CVE-2017-16943-en/), and then a separate blog on indepdently reproducing including how to [build exim and reproduce](https://medium.com/@knownsec404team/exim-uaf-vulnerability-analysis-cve-2017-16943-226daf1e4138). 
* CVE-2017-16944: Remote EXIM hang with report [here](https://bugs.exim.org/show_bug.cgi?id=2201).  This happens in the same version as above (2017-11-23).
* CVE-2018-6789: Published 2018-02-08 9.8 severity. Commit fix referenced [here](https://git.exim.org/exim.git/commit/cf3cd306062a08969c41a1cdd32c6855f1abecf1).  [<4.90.1 exploit](https://www.exploit-db.com/exploits/44571). [Another exploit tested](https://www.exploit-db.com/exploits/45671) on debian exim 4.89/ubuntu exim 4.86_2.
* [CVE-2020-12783](https://bugs.exim.org/show_bug.cgi?id=2571): OOB read on SPA implementations (NTLM). Reported 2020-05-05.
* [CVE-2020-28007 - CVE-2020-28025](https://www.exim.org/static/doc/security/CVE-2020-qualys/CVE-2020-28024-UNGET.txt): reported 2020-10-20, so presumably the code was in revisions before that.  According to CVE details, these all apply to Exim4 before 4.94.2.

  * **Privilege escalation:** CVE-2020-28007, CVE-2020-28008, CVE-2020-28014: exim user to root due to unsafe file handling, e.g., symlink attacks. CVE-2021-27216 allows arbitrary file deletion because of a race condition. 
  * **Local heap overflow: ** CVE-2020-28011, CVE-2020-28010, CVE-2020-28013, CVE-2020-28016 is exim user to root
  * **Unprivileged local user arbitrary command execution:** CVE-2020-28015 (Note: Effect similar to CVE-2020-8794 in OpenSMTPD), CVE-2020-28012, CVE-2020-28009
  * **Unauth'ed RCE but unuseful:** CVE-2020-28017 is an overflow triggered by 50M recipients and potentially >25GB of memory. CVE-2020-28020 is hard to exploit. 
  * **OOB Read (remote?)** CVE-2020-28023, introduced in Exim 4.88, and addressed by developers in July 2020.
  * **Potentially interesting RCE:** 
    * CVE-2020-28021 allows an authenticated remote user to inject new lines into the spool header and execute arbitrary. This would potentially be useful against an ISP where you had an account.  
    * CVE-2020-28022 is a potential remote unauth RCE, but the writeup authors could not do it. 
    * CVE-2020-28026 can be triggered on debian, and potentially RCE but full exploit not shown.
    * CVE-2020-28024, which the authors did not exploit. It requires TLS and TLS-on-connect
    * CVE-2020-28018 is a use-after-free, but this exploit requires multiple connections. It also requires Exim is compiled with OpenSSL, though the default for debian at the time with GnuTLS. **"This use-after-free of a struct gstring (server_corked) and its string buffer (server_corked->s) is the most powerful vulnerability in this advisory"**
    * CVE-2020-28025 is a heap out-of-bounds read that could lead to information disclosure. No exploit explored.
  * **Remote DOS:** CVE-2020-28019 will do stack exhaustion. 



## TODO

* [ ] Add in a check to `store_get_3(int size)` that checks and aborts if `size < 0`. This is checking for the [exploit primitive here](https://www.exim.org/static/doc/security/CVE-2020-qualys/CVE-2020-28024-UNGET.txt). 
* [ ] Set up configuration so exim can run as a user. RIGHT NOW WE NEED TO FUZZ AS ROOT. Make sure Mayhem is set up to do this.

## Building EXIM

* On debian, built with gnutls `apt-get install gnutls-dev pkg-config libpcre3-dev`

* Assuming you are in the `src` directory, and see in this directory `ABOUT`, `ACKNOLWEDGEMENTS`, and so on.

* First,  `mkdir Local` and then copy `src/EDITME` to `Local/Makefile`.

* Set in `Local/Makefile` `EXIM_USER=exim`

* Uncomment in `Local/Makefile`:
  ```
  USE_GNUTLS=yes
  USE_GNUTLS_PC=gnutls gnutls-dane
  ```

* Run:
  ```bash
  make CFLAGS='-g'
  make install
  ```



You can get more verbose output with:

```
make FULLECHO='' CFLAGS='-g' -e
```



## Configuring exim

There are a few configuration rules that will speed things up. 

* Set up `/etc/aliases` so that `postmaster`  gets blackholed. This will prevent analysis from actually creating /var/mail/postmaster mail.  To do so, add to `/etc/aliases` the following: `postmaster: :blackhole:`
* Disable verification in the `acl_check_rcpt`.  Given `MAIL FROM: <boo@blah.com>`, this will try to verify with `blah.com` that `boo@blah.com` is a legitimate email address.
* Set up the right group and mode for mail delivery on debian/ubuntu (which is what I tested this on). This is done by finding the `group = mail` and `mode = 0660` line and uncommenting them.

Here is the diff from the default configure:

```diff
--- configure	2024-02-02 17:24:40.335520836 -0500
+++ configure.orig	2024-02-02 16:34:04.014417611 -0500
@@ -447,7 +447,7 @@
 
   # Deny unless the sender address can be verified.
 
-#  require verify        = sender
+  require verify        = sender
 
   # Accept if the message comes from one of the hosts for which we are an
   # outgoing relay. It is assumed that such hosts are most likely to be MUAs,
@@ -867,8 +867,8 @@
   delivery_date_add
   envelope_to_add
   return_path_add
-  group = mail
-  mode = 0660
+# group = mail
+# mode = 0660
```



## Running Exim

There are several ways to run exim. We'll go over them, and then make a recommendation below for performing Mayhem analysis.

* Check that your exim configuration is valid with `exim -bV`. 
* Run Mayhem analysis in batch mode with `exim -bS`.  Batch mode means that the server doesn't print replies or require a client to read them. The result is analysis does not need to analyze a protocol, but instead a particular message format. 

Before doing analysis, you can test your configuration locally by adding the `-v` (verbosity) flag:

```bash
root@hal:/usr/exim# ./bin/exim -bS -v
LOG: MAIN
  Warning: No server certificate defined; will use a selfsigned one.
 Suggested action: either install a certificate or change tls_advertise_hosts option
LOG: MAIN
  Warning: purging the environment.
 Suggested action: use keep_environment.
LOG: smtp_connection MAIN
  SMTP connection from root
EHLO foo.com
MAIL FROM: boo@boo.com
RCPT TO: postmaster
DATA
test
.
LOG: MAIN
  <= boo@boo.com U=root P=local-bsmtp S=291
LOG: MAIN
  Warning: No server certificate defined; will use a selfsigned one.
 Suggested action: either install a certificate or change tls_advertise_hosts option
delivering 1rW1xz-000QWK-PB
LOG: MAIN
  => dbrumley <postmaster@hal> R=localuser T=local_delivery
LOG: MAIN

```

And then verify mail is present on the system (e.g., with `alpine`, a text-based mail reader).

## Fuzzing with AFL

When building, run:

```
make CC=afl-gcc CFLAGS="-g"
```

In older versions, you may need to add the following to `Local/Makefile`

```
CC=afl-clang
```



and then to fuzz:

```bash
mkdir in out
# Make sure you run as root!
afl-fuzz -x dict.txt -i in -o out -- ./build-Linux-x86_64/exim -bs
```

Make sure you're running this as root, as exim seems to want that.





## Other notes

* `exim -bS` sets `smtp_input = smtp_batched_input = receiving_message = TRUE;` in main:exim.c

* The name=value parameters such as AUTH= are extracted from MAIL FROM and
  RCPT TO commands by `extract_option()`

* Notes to myself:

  * Figure out how to enable PIPELINING. 

    * Related, it seems like X_PIPE_CONNECT should be disabled for CVE-2020-28018. Does this

  * Exim [documentation link](https://www.exim.org/docs.html), with [4.90 specific](https://www.exim.org/exim-html-4.90/doc/html/spec_html/index.html) link. Book (borrow by the hour) [here](https://archive.org/details/eximsmtpmailserv0000haze).

  * By default, logs in `/var/sopol/exim/log` 

  * Example session:
    ```
    exim -bs -v
    helo <host-address>
    mail from: <user>@<host-address>
    rcpt to: <user>@<host-address>
    temporarily rejected RCPT <user>@<host-address>: syntax error in
    "control=dkim_disable_verify"
    ```

    

  * Running:

    * Make sure your hostname is set. We're going to assume it's `forallsecure.local` in this config.
    * Run locally and accept from stdin: `exim4 -bs`
    * Batch SMTP mode where responses are not written: `-bS`. 

  * Building: 

    * Configuration placed in directory `Local`, which has two files: `Local/Makefile, Local/eximon.conf` A template of `Local/Makefile` is given in `src/EDITME`.

    * Three required settings, but a few common (22.3.3 in the book, page 511):
      ```BIN_DIRECTORY=/usr/exim/bin
      BIN_DIRECTORY=/usr/exim/bin
      CONFIGURE_FILE=/usr/exim/configure
      EXIM_USER=exim
      # Drivers
      ROUTER_ACCEPT=yes
      ROUTER_DNSLOOKUP=yes
      ROUTER_IPLITERAL=yes
      ROUTER_MANUALROUTE=yes
      ROUTER_QUERYPROGRAM=yes
      ROUTER_REDIRECT=yes
      TRANSPORT_APPENDFILE=yes
      TRANSPORT_AUTOREPLY=yes
      TRANSPORT_PIPE=yes
      TRANSPORT_SMTP=yes
      AUTH_PLAINTEXT=yes  # AUTH_CRAM_MD5 is another example
      
      # Module choices most common includes lsearch and dbm lookup
      LOOKUP_DBM=yes
      LOOKUP_LSEARCH=yes
      
      # Recommended settings
      LOG_FILE_PATH=/var/log/exim_%slog
      SPOOL_DIRECTORY=/var/spool/exim
      SPOOL_MODE=0640
      ```

  * Testing Exim before turning on:

    * Check that the runtime config is syntactically valid: `exim -bV`

    * Check that it recognizes local mailbox: `exim -v -bt user@your.domain` for local, `exim -v -bt user@somewhere.else.example` for somewhere else.

    * Post directly through Exim:
      ```
      exim postmaster@your.domain
      From: user@your.domain
      To: postmaster@your.domain
      Subject: Testing Exim
      This is a test message
      :.:
      ```

    * `exim -bp` lists messages in the queue (which is really a pool of all messages; no ordering is given)

    * Find the name of the configuration file: `exim -bP configure_file`

    * `qualify_domain = example.com` sets that addresses containing only a local part and no domain are to be turned into complete qualified addressees by appending the domain set.

  * Page 51 has a minimal exim configuration file.

  * If the main part of the configuration (the part before the first `begin` line) begins with an upper-case letter, it's a macro definition.

* 

  * 
* **Exploit primitives**: If a user can pass a negative integer to store.c, which calls `malloc` and `free`. To see this, note that `store_get_3` uses a plain `int` for the size, so if negative the caller can overflow the current block of memory. A subsequent memory allocation can overwrite the beginning of Exim's heap: a relative write-what-where, which bypasses ASLR. An attacker can "back-jump" to overwrite Exim's configuration with `"${run{...}}"` commands to execute arbitrary file commands.
  * 


Interesting from code `exim.c`:
```c
    /* -bS: Read SMTP commands on standard input, but produce no replies -
    all errors are reported by sending messages. */

    else if (Ustrcmp(argrest, "S") == 0)
      smtp_input = smtp_batched_input = receiving_message = TRUE;

    /* -bs: Read SMTP commands on standard input and produce SMTP replies
    on standard output. */


```