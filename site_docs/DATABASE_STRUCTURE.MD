DATABASE STRUCTURE


** USERS **
- name: text field, full name
- username: text field, username used at login
- permissions: Administrator, Analyst, Viewer
- - Administrator: can do all site functions
- - Analyst: cannot delete anything, cannot edite other Analyst users but can adjust Viewer users
- - Viewer: can view site data for the case they are assigned to ONLY (see below for case assignment, this is not the same as the assigned to section of a case); cannot edit/add to a case can only view content (read-only), cannot edit any user data even their own
- email address: text field
- created_by: username who created the user
- created_on: date/time user was created
- active: user account is enabled/disabled
