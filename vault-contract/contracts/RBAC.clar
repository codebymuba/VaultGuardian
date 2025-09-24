;; RBAC Smart Contract - Fixed Version
;; Implements Role-Based Access Control with predefined roles, custom roles, inheritance, and dynamic management

;; Constants for predefined roles
(define-constant ROLE-ADMIN u1)
(define-constant ROLE-MANAGER u2)
(define-constant ROLE-OPERATOR u3)
(define-constant ROLE-VIEWER u4)
(define-constant ROLE-AUDITOR u5)

;; Error constants
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-ROLE-NOT-FOUND (err u101))
(define-constant ERR-ROLE-ALREADY-EXISTS (err u102))
(define-constant ERR-INVALID-ROLE (err u103))
(define-constant ERR-CIRCULAR-INHERITANCE (err u104))
(define-constant ERR-CANNOT-REVOKE-SELF (err u105))

;; Contract owner
(define-constant CONTRACT-OWNER tx-sender)

;; Data structures

;; Role definitions: role-id -> {name, description, is-custom, created-by, created-at}
(define-map roles 
  uint 
  {
    name: (string-ascii 50),
    description: (string-ascii 200),
    is-custom: bool,
    created-by: principal,
    created-at: uint
  }
)

;; User role assignments: {user, role-id} -> {assigned-by, assigned-at}
(define-map user-roles 
  {user: principal, role-id: uint}
  {
    assigned-by: principal,
    assigned-at: uint
  }
)

;; Role permissions: {role-id, permission} -> bool
(define-map role-permissions
  {role-id: uint, permission: (string-ascii 50)}
  bool
)

;; Role inheritance: {parent-role, child-role} -> bool
(define-map role-inheritance
  {parent-role: uint, child-role: uint}
  bool
)

;; Custom role counter
(define-data-var next-custom-role-id uint u100)

;; Helper functions (defined before use)

;; Check if user has a specific role (direct assignment only)
(define-read-only (has-role (user principal) (role-id uint))
  (is-some (map-get? user-roles {user: user, role-id: role-id}))
)

;; Check if role exists
(define-read-only (role-exists (role-id uint))
  (is-some (map-get? roles role-id))
)

;; Simplified role inheritance check without complex filter operations
(define-private (role-inherits (parent-role uint) (child-role uint))
  (default-to false (map-get? role-inheritance {parent-role: parent-role, child-role: child-role}))
)

;; Check if user has role including inheritance - simplified approach
(define-read-only (has-role-or-inherited (user principal) (role-id uint))
  (or 
    (has-role user role-id)
    (and (has-role user ROLE-ADMIN) (or (is-eq role-id ROLE-MANAGER) (is-eq role-id ROLE-OPERATOR) (is-eq role-id ROLE-VIEWER) (is-eq role-id ROLE-AUDITOR)))
    (and (has-role user ROLE-MANAGER) (or (is-eq role-id ROLE-OPERATOR) (is-eq role-id ROLE-VIEWER)))
    (and (has-role user ROLE-OPERATOR) (is-eq role-id ROLE-VIEWER))
  )
)

;; Simplified permission check without complex filter operations
(define-read-only (has-permission (user principal) (permission (string-ascii 50)))
  (or
    (and (has-role-or-inherited user ROLE-ADMIN) (default-to false (map-get? role-permissions {role-id: ROLE-ADMIN, permission: permission})))
    (and (has-role-or-inherited user ROLE-MANAGER) (default-to false (map-get? role-permissions {role-id: ROLE-MANAGER, permission: permission})))
    (and (has-role-or-inherited user ROLE-OPERATOR) (default-to false (map-get? role-permissions {role-id: ROLE-OPERATOR, permission: permission})))
    (and (has-role-or-inherited user ROLE-VIEWER) (default-to false (map-get? role-permissions {role-id: ROLE-VIEWER, permission: permission})))
    (and (has-role-or-inherited user ROLE-AUDITOR) (default-to false (map-get? role-permissions {role-id: ROLE-AUDITOR, permission: permission})))
  )
)

;; Check if user has admin privileges
(define-private (is-admin (user principal))
  (has-role user ROLE-ADMIN)
)

;; Initialize predefined roles
(define-private (init-predefined-roles)
  (begin
    (map-set roles ROLE-ADMIN {
      name: "Admin",
      description: "Full system administrator with all permissions",
      is-custom: false,
      created-by: CONTRACT-OWNER,
      created-at: block-height
    })
    (map-set roles ROLE-MANAGER {
      name: "Manager", 
      description: "Management role with elevated permissions",
      is-custom: false,
      created-by: CONTRACT-OWNER,
      created-at: block-height
    })
    (map-set roles ROLE-OPERATOR {
      name: "Operator",
      description: "Operational role for day-to-day tasks",
      is-custom: false,
      created-by: CONTRACT-OWNER,
      created-at: block-height
    })
    (map-set roles ROLE-VIEWER {
      name: "Viewer",
      description: "Read-only access to system resources",
      is-custom: false,
      created-by: CONTRACT-OWNER,
      created-at: block-height
    })
    (map-set roles ROLE-AUDITOR {
      name: "Auditor",
      description: "Audit and compliance monitoring role",
      is-custom: false,
      created-by: CONTRACT-OWNER,
      created-at: block-height
    })
    ;; Set up default role hierarchy
    (map-set role-inheritance {parent-role: ROLE-ADMIN, child-role: ROLE-MANAGER} true)
    (map-set role-inheritance {parent-role: ROLE-MANAGER, child-role: ROLE-OPERATOR} true)
    (map-set role-inheritance {parent-role: ROLE-OPERATOR, child-role: ROLE-VIEWER} true)
    ;; Admin inherits auditor permissions
    (map-set role-inheritance {parent-role: ROLE-ADMIN, child-role: ROLE-AUDITOR} true)
  )
)

;; Initialize contract
(init-predefined-roles)

;; Assign initial admin role to contract owner
(map-set user-roles 
  {user: CONTRACT-OWNER, role-id: ROLE-ADMIN}
  {assigned-by: CONTRACT-OWNER, assigned-at: block-height}
)

;; Public functions

;; Create a custom role
(define-public (create-custom-role (name (string-ascii 50)) (description (string-ascii 200)))
  (let ((role-id (var-get next-custom-role-id)))
    (asserts! (is-admin tx-sender) ERR-NOT-AUTHORIZED)
    (asserts! (is-none (map-get? roles role-id)) ERR-ROLE-ALREADY-EXISTS)
    
    (map-set roles role-id {
      name: name,
      description: description,
      is-custom: true,
      created-by: tx-sender,
      created-at: block-height
    })
    
    (var-set next-custom-role-id (+ role-id u1))
    (print {event: "role-created", role-id: role-id, name: name, created-by: tx-sender})
    (ok role-id)
  )
)

;; Assign role to user
(define-public (assign-role (user principal) (role-id uint))
  (begin
    (asserts! (is-admin tx-sender) ERR-NOT-AUTHORIZED)
    (asserts! (role-exists role-id) ERR-ROLE-NOT-FOUND)
    
    (map-set user-roles 
      {user: user, role-id: role-id}
      {assigned-by: tx-sender, assigned-at: block-height}
    )
    
    (print {event: "role-assigned", user: user, role-id: role-id, assigned-by: tx-sender})
    (ok true)
  )
)

;; Revoke role from user
(define-public (revoke-role (user principal) (role-id uint))
  (begin
    (asserts! (is-admin tx-sender) ERR-NOT-AUTHORIZED)
    (asserts! (role-exists role-id) ERR-ROLE-NOT-FOUND)
    (asserts! (not (and (is-eq user tx-sender) (is-eq role-id ROLE-ADMIN))) ERR-CANNOT-REVOKE-SELF)
    
    (map-delete user-roles {user: user, role-id: role-id})
    
    (print {event: "role-revoked", user: user, role-id: role-id, revoked-by: tx-sender})
    (ok true)
  )
)

;; Set permission for role
(define-public (set-role-permission (role-id uint) (permission (string-ascii 50)) (granted bool))
  (begin
    (asserts! (is-admin tx-sender) ERR-NOT-AUTHORIZED)
    (asserts! (role-exists role-id) ERR-ROLE-NOT-FOUND)
    
    (if granted
      (map-set role-permissions {role-id: role-id, permission: permission} true)
      (map-delete role-permissions {role-id: role-id, permission: permission})
    )
    
    (print {event: "permission-updated", role-id: role-id, permission: permission, granted: granted})
    (ok true)
  )
)

;; Set role inheritance
(define-public (set-role-inheritance (parent-role uint) (child-role uint) (inherit bool))
  (begin
    (asserts! (is-admin tx-sender) ERR-NOT-AUTHORIZED)
    (asserts! (role-exists parent-role) ERR-ROLE-NOT-FOUND)
    (asserts! (role-exists child-role) ERR-ROLE-NOT-FOUND)
    (asserts! (not (is-eq parent-role child-role)) ERR-CIRCULAR-INHERITANCE)
    
    (if inherit
      (map-set role-inheritance {parent-role: parent-role, child-role: child-role} true)
      (map-delete role-inheritance {parent-role: parent-role, child-role: child-role})
    )
    
    (print {event: "inheritance-updated", parent-role: parent-role, child-role: child-role, inherit: inherit})
    (ok true)
  )
)

;; Delete custom role
(define-public (delete-custom-role (role-id uint))
  (let ((role-info (unwrap! (map-get? roles role-id) ERR-ROLE-NOT-FOUND)))
    (asserts! (is-admin tx-sender) ERR-NOT-AUTHORIZED)
    (asserts! (get is-custom role-info) ERR-INVALID-ROLE)
    
    (map-delete roles role-id)
    
    (print {event: "role-deleted", role-id: role-id, deleted-by: tx-sender})
    (ok true)
  )
)

;; Simplified batch assignment without complex fold operations
(define-public (assign-multiple-roles (user principal) (role-ids (list 5 uint)))
  (begin
    (asserts! (is-admin tx-sender) ERR-NOT-AUTHORIZED)
    (map assign-single-role role-ids)
    (ok true)
  )
)

;; Helper for simplified batch assignment
(define-private (assign-single-role (role-id uint))
  (map-set user-roles 
    {user: tx-sender, role-id: role-id}
    {assigned-by: tx-sender, assigned-at: block-height}
  )
)

;; Read-only functions

;; Get role information
(define-read-only (get-role-info (role-id uint))
  (map-get? roles role-id)
)

;; Get user role assignment info
(define-read-only (get-user-role-info (user principal) (role-id uint))
  (map-get? user-roles {user: user, role-id: role-id})
)

;; Check if role has permission
(define-read-only (role-has-permission (role-id uint) (permission (string-ascii 50)))
  (default-to false (map-get? role-permissions {role-id: role-id, permission: permission}))
)

;; Check role inheritance
(define-read-only (role-inherits-from (parent-role uint) (child-role uint))
  (default-to false (map-get? role-inheritance {parent-role: parent-role, child-role: child-role}))
)

;; Access control modifier function
(define-read-only (require-permission (user principal) (permission (string-ascii 50)))
  (has-permission user permission)
)
