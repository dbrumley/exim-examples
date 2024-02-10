# EXIM Mail Server

## CVE-2017-16944

This is a remote EXIM hang and crash, as reported
[here](https://bugs.exim.org/show_bug.cgi?id=2201).  This happens in the same
version as above (2017-11-23). 

* Reported 2017-11-23 by meh@devco.re. 
* Vulnerability (according to report) is in git master at revision
  01c594601670c7e48e676d6c6d32d0f0084067fa.  
* The initial test was on 4.89. 
* There is an RIP-controllable POC, an updated POC, and the Makefile is given.
  More detailed writeup from
  [devco.re](https://devco.re/blog/2017/12/11/Exim-RCE-advisory-CVE-2017-16943-en/),
  and then a separate blog on indepdently reproducing including how to [build
  exim and
  reproduce](https://medium.com/@knownsec404team/exim-uaf-vulnerability-analysis-cve-2017-16943-226daf1e4138).  

See the [CVE-2017-16944/README.md](./CVE-2017-16944/README.md) for more information.

