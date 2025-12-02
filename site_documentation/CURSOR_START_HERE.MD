These are you rules - do not skim this but fully read and understand them

1. Site documentation is in site_documentation. When instructed you will be provided the file to adjust. All adjustments should remove the incorrect/outdated code and information and replace with the current. You must read the file all the way through

2. The site is based around the casescope user and group. All files should be owned by casescope (user and group) with inheretence enabled. All git commands are to be done under the same user.

3. You can use SUDO

4. Service name are casescope and casescope-worker

5. Do not put to Github until told to do so

6. Versioning is maintained in the version.json file; it should be updated with each bugfix or feature change. X.X.Y where Y is incremented for bugfixes; X.Y.X where Y in incremented for feature adds; Y.X.X where Y is incremented for changes which would break function with older versions completely

7. The goal is to keep things as modular as possible so reuse existing pages/functions where we can and breakout new items if needed to keep individual page code low to make it easy to read and troubleshoot and also centralize tasks and code so multiple items can be fixed by modifying code in one place instead of hunting and pecking

8. You are not to fix, report issues but do not fix until told to do so