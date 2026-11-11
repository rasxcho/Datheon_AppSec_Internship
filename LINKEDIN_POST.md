# LinkedIn post (edit brackets; attach a 45-60 s screen recording)

Just wrapped my Application Security internship project with @Datheon.

What I did, end to end:

1) Found it. A dashboard loaded user data from a URL parameter. Copy the request as cURL, strip every cookie and header, and the API still returned names, emails, phone numbers and internal notes. Change one number and you get someone else's record. Wrote it up as a disclosure report with a CVSS 3.1 score of 7.5 (High).

2) Fixed it. The backend now checks who is asking (401), queries by resource id AND the session owner, and returns the same 404 whether a record is missing or just not yours. 13 integration tests prove User A can't read User B.

3) Secured the session. Replaced token-in-localStorage thinking with signed HttpOnly, SameSite cookies, 15-minute expiry, token rotation, server-side logout, and a sliding-window rate limiter that turns brute-force login attempts into 429s.

The lesson that stuck: being logged in is not the same as being allowed. Every object needs its own authorization check on the server.

Code, PoCs, tests and report: https://github.com/[your-username]/Datheon_AppSec_Internship

#ApplicationSecurity #OWASP #APISecurity #IDOR #BOLA #NodeJS #TypeScript #CyberSecurity #Datheon

## Video outline (about 60 s)
1. (0-15 s) cURL with no cookie returns another person's record; show the probe: "5 of 10 ids returned personal data"
2. (15-30 s) Show the 5-line fix idea: query by id AND owner; rerun the probe: all 401
3. (30-45 s) Login, show HttpOnly cookie in DevTools (not readable from the console), 6th wrong login gets 429
4. (45-60 s) `npm test` green, repo link
