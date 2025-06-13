# excludeCurrentSession và forceLogout - Detailed Explanation

## Overview

Hai fields `excludeCurrentSession` và `forceLogout` là các controls quan trọng để đảm bảo security và user experience khi revoke sessions.

## 1. excludeCurrentSession

### Mục đích
Bảo vệ người dùng khỏi việc vô tình đăng xuất khỏi phiên hiện tại khi revoke sessions.

### Behavior Logic

#### Case 1: `excludeCurrentSession: true` (Default behavior)
```json
{
  "sessionIds": ["session1", "session2", "current-session-id"],
  "excludeCurrentSession": true
}
```

**Result:**
- ✅ Revoke `session1` và `session2`
- ❌ **Auto-exclude** `current-session-id` 
- 🔒 User vẫn đăng nhập ở phiên hiện tại
- 📱 Response: `"status": "auto_protected"`

#### Case 2: `excludeCurrentSession: false`
```json
{
  "sessionIds": ["session1", "session2", "current-session-id"],
  "excludeCurrentSession": false
}
```

**Result:**
- ✅ Revoke tất cả sessions including current session
- ❌ User bị đăng xuất ngay lập tức
- 🚪 Redirect tới login page

#### Case 3: `excludeCurrentSession` không được specify (Auto-detection)
```json
{
  "sessionIds": ["session1", "session2", "current-session-id"]
  // No excludeCurrentSession field
}
```

**System behavior:**
- 🤖 **Smart detection**: Tự động phát hiện current session trong list
- 🛡️ **Auto-protect**: Exclude current session để tránh logout bất ngờ
- 📱 Response: `"status": "auto_protected"`

---

## 2. forceLogout

### Mục đích
Explicit confirmation cho các actions nguy hiểm có thể khiến user bị logout.

### Behavior Logic

#### Case 1: `forceLogout: false` (Default - Safe mode)
```json
{
  "deviceIds": [1, 2],  // Device 2 là current device
  "forceLogout": false
}
```

**Result:**
- 🚫 **Block dangerous action**
- 📢 Require user confirmation
- 📱 Response: `"status": "confirmation_needed"`

#### Case 2: `forceLogout: true` (Confirmed dangerous action)
```json
{
  "deviceIds": [1, 2],  // Device 2 là current device  
  "forceLogout": true
}
```

**Result:**
- ✅ **Execute action** kể cả khi nguy hiểm
- 🚪 User có thể bị logout nếu current device bị revoke
- ⚠️ User đã confirm họ hiểu hậu quả

#### Case 3: `forceLogout` không được specify (Auto safety check)
```json
{
  "deviceIds": [1, 2]  // Device 2 là current device
  // No forceLogout field
}
```

**System behavior:**
- 🔍 **Danger analysis**: Check xem action có nguy hiểm không
- 🛡️ **Safety first**: Block nếu có thể gây logout
- 📱 Response: `"status": "confirmation_needed"`

---

## Combination Examples

### Example 1: Safe bulk revoke
```json
{
  "sessionIds": ["old-session-1", "old-session-2", "current-session"],
  "excludeCurrentSession": true,
  "forceLogout": false
}
```

**Result:**
- ✅ Revoke old sessions
- 🛡️ Protect current session
- 📱 `"status": "success"` hoặc `"auto_protected"`

### Example 2: Dangerous logout everywhere
```json
{
  "deviceIds": [1, 2, 3],  // Tất cả devices including current
  "excludeCurrentSession": false,
  "forceLogout": true
}
```

**Result:**
- ✅ Revoke ALL devices/sessions
- 🚪 User logout ngay lập tức
- 📱 Clear cookies, redirect to login

### Example 3: Request confirmation for dangerous action
```json
{
  "deviceIds": [2],  // Current device
  "excludeCurrentSession": false
  // No forceLogout = needs confirmation
}
```

**Result:**
- 🚫 Block action
- 📱 Response: `"status": "confirmation_needed"`
- 💬 Message: "This will log you out. Continue?"

### Example 4: Auto-protection (Recommended)
```json
{}  // Empty object hoặc không specify fields
```

**Result:**
- 🤖 **Smart defaults**: System tự quyết định safe behavior
- 🛡️ **Auto-exclude** current session
- 📱 `"status": "auto_protected"`

---

## Decision Matrix

| Scenario | excludeCurrentSession | forceLogout | Result |
|----------|----------------------|-------------|---------|
| Normal revoke other sessions | `true` or unspecified | `false` or unspecified | ✅ Safe revoke |
| Logout everywhere (confirmed) | `false` | `true` | 🚪 Full logout |
| Dangerous action without confirmation | `false` | `false` or unspecified | 🚫 Block + ask confirmation |
| Auto-protection | unspecified | unspecified | 🛡️ Smart safety |

---

## Frontend Implementation

### Step 1: Default safe request
```javascript
// User clicks "Revoke selected sessions"
const response = await fetch('/api/sessions/revoke', {
  method: 'POST',
  body: JSON.stringify({
    sessionIds: selectedSessionIds
    // No excludeCurrentSession, no forceLogout = auto-safe
  })
})
```

### Step 2: Handle responses
```javascript
switch (response.status) {
  case 'success':
    showSuccessMessage(response.message)
    refreshSessionsList()
    break
    
  case 'auto_protected':
    showInfoMessage("Current session was automatically protected")
    refreshSessionsList()
    break
    
  case 'confirmation_needed':
    showConfirmDialog({
      message: response.message,
      onConfirm: () => retryWithForceLogout(selectedSessionIds)
    })
    break
}

function retryWithForceLogout(sessionIds) {
  return fetch('/api/sessions/revoke', {
    method: 'POST',
    body: JSON.stringify({
      sessionIds,
      excludeCurrentSession: false,  // Allow current session revoke
      forceLogout: true             // Confirm dangerous action
    })
  })
}
```

---

## Security Benefits

1. **Prevent accidental logout**: User không bị logout bất ngờ
2. **Explicit confirmation**: Dangerous actions require clear consent
3. **Smart defaults**: System behavior secure by default
4. **Flexible control**: Advanced users có full control
5. **Clear feedback**: Response messages rõ ràng về hành động đã thực hiện

---

## Best Practices

### For Frontend Developers:
1. **Always handle all response statuses**: `success`, `auto_protected`, `confirmation_needed`
2. **Default to safe behavior**: Không specify fields khi không chắc chắn
3. **Show clear confirmations**: Explain consequences của dangerous actions
4. **Provide escape routes**: Always có option để cancel dangerous actions

### For API Consumers:
1. **Use empty body `{}` for safe defaults**
2. **Only set `forceLogout: true` after user confirmation**
3. **Never set `excludeCurrentSession: false` without warning user**
4. **Handle `auto_protected` responses gracefully**
