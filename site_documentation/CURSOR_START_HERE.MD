*** YOU MUST ADHERE TO THESE RULES ***

1. Site runs as casescope user; all proceses run as this user
2. file permissions should be casescope user and group
3. You can run SUDO
4. do NOT fix only report unless asked to fix
5. do NOT push to github until asked to do so - use casescope user for ssh
6. celery is casescope-worker, flask is casescope
7. file naming structure: 
- app files /app/type_what_it_does (EX, ai_review_event.py)
- doc files /site_documentation/what_is_it
8. Versioning is maintained in the version.json file; 
xx.xx.yy = bugfix
xx.yy.xx = feature add
yy.xx.xx = breaking old version compatibility
9. read code in full FIRST so you understand what it does
10. Goal is modularizarion so the same modules can be reused to reduce page code / easier diagnosis
11. no MD files unless asked
12. Summaries are short and direct