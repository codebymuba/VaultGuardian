;; VaultGuardian RBAC Foundation Contract
;; Implements enterprise-grade role-based access control with inheritance and dynamic management
;; ===========================================
;; CONSTANTS AND ERROR CODES
;; ===========================================

(define-constant CONTRACT-OWNER tx-sender)
(define-constant ERR-UNAUTHORIZED (err u100))
(define-constant ERR-ROLE-NOT-FOUND (err u101))
(define-constant ERR-ROLE-ALREADY-EXISTS (err u102))
(define-constant ERR-INVALID-ROLE-HIERARCHY (err u103))
(define-constant ERR-CANNOT-REVOKE-SELF (err u104))
(define-constant ERR-ROLE-IN-USE (err u105))
(define-constant ERR-INVALID-PERMISSION (err u106))
(define-constant ERR-CIRCULAR-INHERITANCE (err u107))

;; Predefined role IDs
(define-constant ROLE-ADMIN u1)
(define-constant ROLE-MANAGER u2)
(define-constant ROLE-OPERATOR u3)
(define-constant ROLE-VIEWER u4)
(define-constant ROLE-AUDITOR u5)

;; Permission constants
(define-constant PERM-CREATE-ROLE u1)
(define-constant PERM-DELETE-ROLE u2)
(define-constant PERM-ASSIGN-ROLE u3)
(define-constant PERM-REVOKE-ROLE u4)
(define-constant PERM-MANAGE-PERMISSIONS u5)
(define-constant PERM-VIEW-USERS u6)
(define-constant PERM-AUDIT-ACCESS u7)
(define-constant PERM-TRANSFER-ASSETS u8)
(define-constant PERM-APPROVE-TRANSACTIONS u9)
(define-constant PERM-EMERGENCY-STOP u10)

;; ===========================================
;; DATA STRUCTURES
;; ===========================================

;; Role definition structure
(define-map roles
  { role-id: uint }
  {
    name: (string-ascii 50),
    description: (string-ascii 200),
    parent-role: (optional uint),
    is-active: bool,
    created-at: uint,
    created-by: principal
  }
)

;; Role permissions mapping
(define-map role-permissions
  { role-id: uint, permission-id: uint }
  { 
    granted: bool, 
    granted-at: uint, 
    granted-by: principal 
  }
)

;; User role assignments
(define-map user-roles
  { user: principal, role-id: uint }
  {
    assigned-at: uint,
    assigned-by: principal,
    expires-at: (optional uint),
    is-active: bool
  }
)

;; Role hierarchy tracking (for inheritance)
(define-map role-hierarchy
  { child-role: uint, parent-role: uint }
  { depth: uint }
)

;; Custom role counter
(define-data-var next-role-id uint u6)

;; Contract pause state
(define-data-var contract-paused bool false)

;; ===========================================
;; INITIALIZATION
;; ===========================================

;; Initialize predefined roles
(map-set roles { role-id: ROLE-ADMIN }
  {
    name: "Administrator",
    description: "Full system access with all permissions",
    parent-role: none,
    is-active: true,
    created-at: block-height,
    created-by: CONTRACT-OWNER
  }
)

(map-set roles { role-id: ROLE-MANAGER }
  {
    name: "Manager",
    description: "Management level access with delegation capabilities",
    parent-role: (some ROLE-ADMIN),
    is-active: true,
    created-at: block-height,
    created-by: CONTRACT-OWNER
  }
)

(map-set roles { role-id: ROLE-OPERATOR }
  {
    name: "Operator",
    description: "Operational access for day-to-day activities",
    parent-role: (some ROLE-MANAGER),
    is-active: true,
    created-at: block-height,
    created-by: CONTRACT-OWNER
  }
)

(map-set roles { role-id: ROLE-VIEWER }
  {
    name: "Viewer",
    description: "Read-only access to system resources",
    parent-role: none,
    is-active: true,
    created-at: block-height,
    created-by: CONTRACT-OWNER
  }
)

(map-set roles { role-id: ROLE-AUDITOR }
  {
    name: "Auditor",
    description: "Audit and compliance access with specialized permissions",
    parent-role: (some ROLE-VIEWER),
    is-active: true,
    created-at: block-height,
    created-by: CONTRACT-OWNER
  }
)

;; Initialize admin permissions
(map-set role-permissions { role-id: ROLE-ADMIN, permission-id: PERM-CREATE-ROLE }
  { granted: true, granted-at: block-height, granted-by: CONTRACT-OWNER })
(map-set role-permissions { role-id: ROLE-ADMIN, permission-id: PERM-DELETE-ROLE }
  { granted: true, granted-at: block-height, granted-by: CONTRACT-OWNER })
(map-set role-permissions { role-id: ROLE-ADMIN, permission-id: PERM-ASSIGN-ROLE }
  { granted: true, granted-at: block-height, granted-by: CONTRACT-OWNER })
(map-set role-permissions { role-id: ROLE-ADMIN, permission-id: PERM-REVOKE-ROLE }
  { granted: true, granted-at: block-height, granted-by: CONTRACT-OWNER })
(map-set role-permissions { role-id: ROLE-ADMIN, permission-id: PERM-MANAGE-PERMISSIONS }
  { granted: true, granted-at: block-height, granted-by: CONTRACT-OWNER })
(map-set role-permissions { role-id: ROLE-ADMIN, permission-id: PERM-VIEW-USERS }
  { granted: true, granted-at: block-height, granted-by: CONTRACT-OWNER })
(map-set role-permissions { role-id: ROLE-ADMIN, permission-id: PERM-AUDIT-ACCESS }
  { granted: true, granted-at: block-height, granted-by: CONTRACT-OWNER })
(map-set role-permissions { role-id: ROLE-ADMIN, permission-id: PERM-TRANSFER-ASSETS }
  { granted: true, granted-at: block-height, granted-by: CONTRACT-OWNER })
(map-set role-permissions { role-id: ROLE-ADMIN, permission-id: PERM-APPROVE-TRANSACTIONS }
  { granted: true, granted-at: block-height, granted-by: CONTRACT-OWNER })
(map-set role-permissions { role-id: ROLE-ADMIN, permission-id: PERM-EMERGENCY-STOP }
  { granted: true, granted-at: block-height, granted-by: CONTRACT-OWNER })

;; Assign initial admin role to contract owner
(map-set user-roles
  { user: CONTRACT-OWNER, role-id: ROLE-ADMIN }
  {
    assigned-at: block-height,
    assigned-by: CONTRACT-OWNER,
    expires-at: none,
    is-active: true
  }
)

;; ===========================================
;; HELPER FUNCTIONS
;; ===========================================

;; Check if contract is paused
(define-private (is-contract-paused)
  (var-get contract-paused)
)

;; Check if user has a specific role
(define-read-only (has-role (user principal) (role-id uint))
  (match (map-get? user-roles { user: user, role-id: role-id })
    assignment (and
      (get is-active assignment)
      (match (get expires-at assignment)
        expiry (> expiry block-height)
        true
      )
    )
    false
  )
)

;; ;; Get all active roles for a user
;; (define-read-only (get-user-active-roles (user principal))
;;   (filter 
;;     ;; Define the predicate function properly
;;     (define-private (is-active-role (role-id uint))
;;       (has-role user role-id)
;;     )
;;     is-active-role
;;     (list ROLE-ADMIN ROLE-MANAGER ROLE-OPERATOR ROLE-VIEWER ROLE-AUDITOR)
;;   )
;; )

(define-read-only (get-user-active-roles (user principal))
  (filter 
    ;; Pass only the predicate function reference
    (lambda (role-id) (has-role user role-id))
    (list ROLE-ADMIN ROLE-MANAGER ROLE-OPERATOR ROLE-VIEWER ROLE-AUDITOR)
  )
)

;; Check if role has permission (including inherited) - MOVED UP BEFORE has-permission
(define-private (role-has-permission-recursive (role-id uint) (permission-id uint))
  (role-has-permission-with-depth role-id permission-id u0)
)

;; Helper function with depth tracking to prevent infinite recursion - MOVED UP
(define-private (role-has-permission-with-depth (role-id uint) (permission-id uint) (depth uint))
  (if (> depth u10) ;; Prevent infinite recursion (max depth 10)
    false
    (or
      ;; Check direct permission
      (is-some (map-get? role-permissions { role-id: role-id, permission-id: permission-id }))
      ;; Check inherited permission from parent
      (match (map-get? roles { role-id: role-id })
        role-data (match (get parent-role role-data)
          parent-id (role-has-permission-with-depth parent-id permission-id (+ depth u1))
          false
        )
        false
      )
    )
  )
)

;; Check if user has permission (including inherited permissions) - NOW PROPERLY ORDERED
(define-read-only (has-permission (user principal) (permission-id uint))
  (let ((user-roles-list (get-user-active-roles user)))
    (> (len (filter (lambda (role-id) (role-has-permission-recursive role-id permission-id)) user-roles-list)) u0)
  )
)

;; Remove the old check-inherited-permission function as it's no longer needed
;; The logic is now integrated into role-has-permission-with-depth

;; Check for circular inheritance
(define-private (would-create-circular-inheritance (child-role uint) (parent-role uint))
  (or
    (is-eq child-role parent-role)
    (is-descendant-of parent-role child-role)
  )
)

;; Check if role A is descendant of role B
(define-private (is-descendant-of (role-a uint) (role-b uint))
  (match (map-get? roles { role-id: role-a })
    role-data (match (get parent-role role-data)
      parent-id (or
        (is-eq parent-id role-b)
        (is-descendant-of parent-id role-b)
      )
      false
    )
    false
  )
)

;; ===========================================
;; ADMINISTRATIVE FUNCTIONS
;; ===========================================

;; Create a new custom role
(define-public (create-role (name (string-ascii 50)) (description (string-ascii 200)) (parent-role (optional uint)))
  (let ((new-role-id (var-get next-role-id)))
    (asserts! (not (is-contract-paused)) ERR-UNAUTHORIZED)
    (asserts! (has-permission tx-sender PERM-CREATE-ROLE) ERR-UNAUTHORIZED)
    
    ;; Validate parent role exists if specified
    (match parent-role
      parent-id (asserts! (is-some (map-get? roles { role-id: parent-id })) ERR-ROLE-NOT-FOUND)
      true
    )
    
    ;; Check for circular inheritance
    (match parent-role
      parent-id (asserts! (not (would-create-circular-inheritance new-role-id parent-id)) ERR-CIRCULAR-INHERITANCE)
      true
    )
    
    ;; Create the role
    (map-set roles { role-id: new-role-id }
      {
        name: name,
        description: description,
        parent-role: parent-role,
        is-active: true,
        created-at: block-height,
        created-by: tx-sender
      }
    )
    
    ;; Update role hierarchy if parent exists
    (match parent-role
      parent-id (map-set role-hierarchy { child-role: new-role-id, parent-role: parent-id } { depth: u1 })
      true
    )
    
    ;; Increment role counter
    (var-set next-role-id (+ new-role-id u1))
    (print { event: "role-created", role-id: new-role-id, name: name, created-by: tx-sender })
    (ok new-role-id)
  )
)

;; Assign role to user
(define-public (assign-role (user principal) (role-id uint) (expires-at (optional uint)))
  (begin
    (asserts! (not (is-contract-paused)) ERR-UNAUTHORIZED)
    (asserts! (has-permission tx-sender PERM-ASSIGN-ROLE) ERR-UNAUTHORIZED)
    (asserts! (is-some (map-get? roles { role-id: role-id })) ERR-ROLE-NOT-FOUND)
    
    ;; Assign the role
    (map-set user-roles { user: user, role-id: role-id }
      {
        assigned-at: block-height,
        assigned-by: tx-sender,
        expires-at: expires-at,
        is-active: true
      }
    )
    (print { event: "role-assigned", user: user, role-id: role-id, assigned-by: tx-sender })
    (ok true)
  )
)

;; Revoke role from user
(define-public (revoke-role (user principal) (role-id uint))
  (begin
    (asserts! (not (is-contract-paused)) ERR-UNAUTHORIZED)
    (asserts! (has-permission tx-sender PERM-REVOKE-ROLE) ERR-UNAUTHORIZED)
    (asserts! (not (and (is-eq user tx-sender) (is-eq role-id ROLE-ADMIN))) ERR-CANNOT-REVOKE-SELF)
    
    ;; Deactivate the role assignment
    (match (map-get? user-roles { user: user, role-id: role-id })
      assignment (begin
        (map-set user-roles { user: user, role-id: role-id }
          (merge assignment { is-active: false })
        )
        (print { event: "role-revoked", user: user, role-id: role-id, revoked-by: tx-sender })
        (ok true)
      )
      ERR-ROLE-NOT-FOUND
    )
  )
)

;; Grant permission to role
(define-public (grant-permission (role-id uint) (permission-id uint))
  (begin
    (asserts! (not (is-contract-paused)) ERR-UNAUTHORIZED)
    (asserts! (has-permission tx-sender PERM-MANAGE-PERMISSIONS) ERR-UNAUTHORIZED)
    (asserts! (is-some (map-get? roles { role-id: role-id })) ERR-ROLE-NOT-FOUND)
    (asserts! (<= permission-id PERM-EMERGENCY-STOP) ERR-INVALID-PERMISSION)
    
    (map-set role-permissions { role-id: role-id, permission-id: permission-id }
      {
        granted: true,
        granted-at: block-height,
        granted-by: tx-sender
      }
    )
    (print { event: "permission-granted", role-id: role-id, permission-id: permission-id, granted-by: tx-sender })
    (ok true)
  )
)

;; Revoke permission from role
(define-public (revoke-permission (role-id uint) (permission-id uint))
  (begin
    (asserts! (not (is-contract-paused)) ERR-UNAUTHORIZED)
    (asserts! (has-permission tx-sender PERM-MANAGE-PERMISSIONS) ERR-UNAUTHORIZED)
    
    (map-delete role-permissions { role-id: role-id, permission-id: permission-id })
    (print { event: "permission-revoked", role-id: role-id, permission-id: permission-id, revoked-by: tx-sender })
    (ok true)
  )
)

;; Update role hierarchy
(define-public (update-role-parent (role-id uint) (new-parent (optional uint)))
  (begin
    (asserts! (not (is-contract-paused)) ERR-UNAUTHORIZED)
    (asserts! (has-permission tx-sender PERM-MANAGE-PERMISSIONS) ERR-UNAUTHORIZED)
    (asserts! (is-some (map-get? roles { role-id: role-id })) ERR-ROLE-NOT-FOUND)
    
    ;; Validate new parent exists if specified
    (match new-parent
      parent-id (asserts! (is-some (map-get? roles { role-id: parent-id })) ERR-ROLE-NOT-FOUND)
      true
    )
    
    ;; Check for circular inheritance
    (match new-parent
      parent-id (asserts! (not (would-create-circular-inheritance role-id parent-id)) ERR-CIRCULAR-INHERITANCE)
      true
    )
    
    ;; Update the role
    (match (map-get? roles { role-id: role-id })
      role-data (begin
        (map-set roles { role-id: role-id }
          (merge role-data { parent-role: new-parent })
        )
        (print { event: "role-hierarchy-updated", role-id: role-id, new-parent: new-parent, updated-by: tx-sender })
        (ok true)
      )
      ERR-ROLE-NOT-FOUND
    )
  )
)

;; ===========================================
;; READ-ONLY FUNCTIONS
;; ===========================================

;; Get role information
(define-read-only (get-role (role-id uint))
  (map-get? roles { role-id: role-id })
)

;; Get user role assignment
(define-read-only (get-user-role-assignment (user principal) (role-id uint))
  (map-get? user-roles { user: user, role-id: role-id })
)

;; Check if role has specific permission (direct only)
(define-read-only (role-has-permission (role-id uint) (permission-id uint))
  (is-some (map-get? role-permissions { role-id: role-id, permission-id: permission-id }))
)

;; Get role permissions (simplified - returns if role has each permission)
(define-read-only (get-role-permissions (role-id uint))
  {
    create-role: (role-has-permission-recursive role-id PERM-CREATE-ROLE),
    delete-role: (role-has-permission-recursive role-id PERM-DELETE-ROLE),
    assign-role: (role-has-permission-recursive role-id PERM-ASSIGN-ROLE),
    revoke-role: (role-has-permission-recursive role-id PERM-REVOKE-ROLE),
    manage-permissions: (role-has-permission-recursive role-id PERM-MANAGE-PERMISSIONS),
    view-users: (role-has-permission-recursive role-id PERM-VIEW-USERS),
    audit-access: (role-has-permission-recursive role-id PERM-AUDIT-ACCESS),
    transfer-assets: (role-has-permission-recursive role-id PERM-TRANSFER-ASSETS),
    approve-transactions: (role-has-permission-recursive role-id PERM-APPROVE-TRANSACTIONS),
    emergency-stop: (role-has-permission-recursive role-id PERM-EMERGENCY-STOP)
  }
)

;; Get contract status
(define-read-only (get-contract-status)
  {
    paused: (var-get contract-paused),
    next-role-id: (var-get next-role-id),
    owner: CONTRACT-OWNER
  }
)

;; ===========================================
;; EMERGENCY FUNCTIONS
;; ===========================================

;; Pause contract (admin only)
(define-public (pause-contract)
  (begin
    (asserts! (has-role tx-sender ROLE-ADMIN) ERR-UNAUTHORIZED)
    (var-set contract-paused true)
    (print { event: "contract-paused", paused-by: tx-sender })
    (ok true)
  )
)

;; Unpause contract (admin only)
(define-public (unpause-contract)
  (begin
    (asserts! (has-role tx-sender ROLE-ADMIN) ERR-UNAUTHORIZED)
    (var-set contract-paused false)
    (print { event: "contract-unpaused", unpaused-by: tx-sender })
    (ok true)
  )
)

;; Emergency role assignment (admin only)
(define-public (emergency-assign-admin (user principal))
  (begin
    (asserts! (has-role tx-sender ROLE-ADMIN) ERR-UNAUTHORIZED)
    (map-set user-roles { user: user, role-id: ROLE-ADMIN }
      {
        assigned-at: block-height,
        assigned-by: tx-sender,
        expires-at: none,
        is-active: true
      }
    )
    (print { event: "emergency-admin-assigned", user: user, assigned-by: tx-sender })
    (ok true)
  )
)
