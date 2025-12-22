# Case Management Permissions - CaseScope 2026

## Permission Matrix

| Action | Administrator | Analyst | Viewer (Read-Only) |
|--------|--------------|---------|-------------------|
| **View Select Case Page** | ✅ Yes | ✅ Yes | ❌ No (auto-redirect to assigned case) |
| **Create New Case** | ✅ Yes | ✅ Yes | ❌ No |
| **Edit Case** | ✅ Yes | ✅ Yes | ❌ No |
| **Delete Case** | ✅ Yes | ❌ No | ❌ No |
| **View Case Dashboard** | ✅ All cases | ✅ All cases | ✅ Assigned case only |
| **Edit EDR Reports** | ✅ Yes | ✅ Yes | ❌ No (read-only) |

---

## Implementation Details

### Case Creation (`POST /case/create`)
**Allowed Roles**: Administrator, Analyst

```python
if current_user.role == 'read-only':
    return jsonify({'error': 'You do not have permission to create cases'}), 403
```

**Access Control**:
- ✅ Administrators can create cases
- ✅ Analysts can create cases
- ❌ Viewers blocked with 403 error

**UI Control**:
- "New Case" button only visible to admins and analysts
- Button hidden for viewers in template

---

### Case Editing (`POST /case/<id>/edit`)
**Allowed Roles**: Administrator, Analyst

```python
if current_user.role == 'read-only':
    return jsonify({'error': 'You do not have permission to edit cases'}), 403
```

**Access Control**:
- ✅ Administrators can edit any case
- ✅ Analysts can edit any case
- ❌ Viewers blocked with 403 error

**UI Control**:
- "Edit Case" button only visible to admins and analysts
- Button hidden for viewers in template

---

### Case Deletion (`POST /case/<id>/delete`)
**Allowed Roles**: Administrator ONLY

```python
if current_user.role != 'administrator':
    return jsonify({'error': 'Only administrators can delete cases'}), 403
```

**Access Control**:
- ✅ Administrators can delete cases (with required reason)
- ❌ Analysts blocked with 403 error
- ❌ Viewers blocked with 403 error

**UI Control**:
- "Delete" button only visible to administrators
- Actions column only shown to administrators in table

**Additional Requirements**:
- Deletion reason required (minimum 10 characters)
- Double confirmation (reason prompt + confirm dialog)
- Full audit trail with reason preserved

---

### Select Case Page (`GET /case/select`)
**Allowed Access**: Administrator, Analyst

**Viewer Behavior**:
```python
if current_user.role == 'read-only':
    if current_user.case_assigned:
        # Redirect directly to their case
        return redirect(url_for('case.case_dashboard', case_id=current_user.case_assigned))
    else:
        flash('No case assigned to your account. Contact an administrator.', 'warning')
        return redirect(url_for('index'))
```

**Access Control**:
- ✅ Administrators see all cases in table
- ✅ Analysts see all cases in table
- ❌ Viewers automatically redirected to their assigned case (no case selection)

---

### Case Dashboard (`GET /case/dashboard/<id>`)
**Allowed Access**: All roles (with restrictions)

**Access Control**:
```python
if current_user.role == 'read-only':
    if case.id != current_user.case_assigned:
        flash('You do not have access to this case', 'error')
        return redirect(url_for('index'))
```

**Behavior by Role**:
- ✅ **Administrators**: Can view any case dashboard
- ✅ **Analysts**: Can view any case dashboard
- ⚠️ **Viewers**: Can only view their assigned case
  - Attempting to view other cases results in access denied error
  - Redirected to homepage with error message

---

## UI Element Visibility

### Case Dashboard Header

**Administrators & Analysts**:
```html
<button class="btn btn-primary" onclick="openEditCaseModal()">
    Edit Case
</button>
```

**Viewers**:
- No "Edit Case" button shown
- Dashboard is read-only

---

### Select Case Page Header

**Administrators & Analysts**:
```html
<button class="btn btn-primary" onclick="openNewCaseModal()">
    New Case
</button>
```

**Viewers**:
- Entire page inaccessible (redirected to assigned case)

---

### Select Case Table - Actions Column

**Administrators Only**:
```html
<th style="width: 100px;">Actions</th>
...
<button class="btn btn-danger btn-sm" onclick="deleteCase(...)">
    Delete
</button>
```

**Analysts & Viewers**:
- Actions column not displayed
- Delete button not available

---

## Audit Logging

All case operations are fully audited:

### Case Creation
- **Action**: `create_case`
- **Logged**: case_id, case_name, created_by, company, status, assigned_to, opensearch_index

### Case Modification
- **Action**: `modify_case`
- **Logged**: case_id, case_name, modified_by, detailed changes (old→new values)

### Case Deletion
- **Action**: `delete_case`
- **Logged**: case_id, case_name, deleted_by, reason (required), company, status, opensearch_index

---

## Permission Enforcement Layers

### 1. Route Decorators
```python
@login_required  # All case routes require authentication
```

### 2. Role Checks in Route Logic
```python
if current_user.role == 'read-only':
    return jsonify({'error': 'Access denied'}), 403

if current_user.role != 'administrator':
    return jsonify({'error': 'Administrator access required'}), 403
```

### 3. Template Conditionals
```jinja2
{% if current_user.role != 'read-only' %}
    <button>Edit Case</button>
{% endif %}

{% if current_user.role == 'administrator' %}
    <button>Delete</button>
{% endif %}
```

### 4. JavaScript Validation
- Frontend validates permissions before API calls
- Provides immediate feedback to users
- Backend still enforces all permissions (defense in depth)

---

## Testing Checklist

### As Administrator
- [x] Can access Select Case page
- [x] Can create new cases
- [x] Can edit any case
- [x] Can delete any case (with reason)
- [x] Can view any case dashboard
- [x] See "New Case" button
- [x] See "Edit Case" button
- [x] See "Delete" buttons in table

### As Analyst
- [x] Can access Select Case page
- [x] Can create new cases
- [x] Can edit any case
- [x] Cannot delete cases (no delete buttons shown)
- [x] Can view any case dashboard
- [x] See "New Case" button
- [x] See "Edit Case" button
- [x] No "Actions" column in table

### As Viewer (Read-Only)
- [x] Cannot access Select Case page (auto-redirect to assigned case)
- [x] Cannot create cases (no UI access)
- [x] Cannot edit cases (no "Edit Case" button)
- [x] Cannot delete cases (no UI access)
- [x] Can only view assigned case dashboard
- [x] Blocked from viewing other cases (403 error)
- [x] EDR reports are read-only (cannot save)

---

## Security Notes

1. **Defense in Depth**: Permissions enforced at multiple layers
2. **Immutable Audit Trail**: All actions logged, cannot be deleted
3. **Required Deletion Reason**: Administrators must justify case deletions
4. **Session Management**: Case selection stored in server-side session
5. **Access Logging**: All permission denials logged for security review
