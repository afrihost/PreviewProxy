# preview
Web based HTTP proxy to preview sites before DNS changes

## Features
The proxy server makes the connection to the server on your behalf:

* You don't have to change your hosts file
* URLs on your site are redirected to this proxy server
* If you browse away from the test site to a live site, then you are redirected to that site
* HTTP basic authentication works
* Cookies work, but might be a little weird (promiscuous)

## Limitations
A few things are not supported:

* This proxy does not support partial loading: you have to wait for the proxy to get the whole page and ajust the links before it sends it back to you.
* You can expect it to be slow, because HTML pages are decomposed and rewritten, by PHP, an interpreted language..
* Javascript-heavy and flash sites tend to end up loading the "real" site, since host names and IP addresses in scripts are generally not rewritten.
* Meta refresh requests with an absolute URL are not rewritten.
* Non-HTTP protocols, and HTTP on ports other than port 80 are not supported (most of these are not name based virtual hosts anyhow, so you can browse to them directly). Lately https on port 443 is vaguely supported, although without any trace of SSL certificate verification, which makes it just a little bit worse than useless, and it has not been tested with SNI.

If your new site and your old site are identical, you should use a browser plugin to show which URLs you are visiting (e.g. firebug for firefox, which is now defunct).

## Bugs
Yep, there's bugs, there are, and not just in the grammar of this sentence. If you see one, don't panic - your site probably looks fine!

*  Error handling is pretty much non-existent - expect blank pages.
*  The proxy can confuse character set encodings, and leave strange droppings like Â in your output (especially when running on CentOS 5.x).
*  This proxy should not be used for security sensitive work, since different sites are rewritten into a single domain. Also, there's no encryption.
*  The HTTP referer header is not handled consistently.
*  Links to foreign sites may be rejected by the server of the IP address you give: the software is too dumb to figure out whether you want the real fbcdn.com or the fbcdn.com at the IP address you supplied.
*  This service is supplied as-is without any guarantee as to whether it works, etc. Any assumptions you make about its manner of operation are entirely your own.
 
