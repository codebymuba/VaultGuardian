;; Permission Management System
;; Implements granular permissions, templates, and dynamic adjustments

;; Constants
(define-constant CONTRACT-OWNER tx-sender)
(define-constant ERR-UNAUTHORIZED (err u100))
(define-constant ERR-PERMISSION-NOT-FOUND (err u101))
(define-constant ERR-INVALID-PERMISSION (err u102))
(define-constant ERR-PERMISSION-EXPIRED (err u103))
(define-constant ERR-THRESHOLD-NOT-MET (err u104))
(define-constant ERR-TEMPLATE-NOT-FOUND (err u105))
(define-constant ERR-INVALID-TEMPLATE (err u106))

;; Permission Types
(define-constant PERMISSION-TRANSFER u1)
(define-constant PERMISSION-APPROVE u2)
(define-constant PERMISSION-BURN u4)
(define-constant PERMISSION-MINT u8)
(define-constant PERMISSION-READ u16)
(define-constant PERMISSION-WRITE u32)
(define-constant PERMISSION-EXECUTE u64)
(define-constant PERMISSION-DELEGATE u128)

;; Data Structures

;; Individual Permission Structure
(define-map user-permissions
  { user: principal, asset: (string-ascii 64), operation: uint }
  {
    granted: bool,
    threshold: uint,
    expiry: (optional uint),
    granted-by: principal,
    granted-at: uint
  }
)

;; Permission Templates
(define-map permission-templates
  { template-id: uint }
  {
    name: (string-ascii 64),
    permissions: uint, ;; Bitfield of permissions
    threshold: uint,
    duration: (optional uint),
    created-by: principal,
    version: uint,
    active: bool
  }
)

;; User Template Assignments
(define-map user-template-assignments
  { user: principal, template-id: uint }
  {
    assigned-at: uint,
    assigned-by: principal,
    expiry: (optional uint),
    active: bool
  }
)

;; Dynamic Permission Rules
(define-map dynamic-permission-rules
  { rule-id: uint }
  {
    name: (string-ascii 64),
    condition-type: uint, ;; 1=time-based, 2=value-based, 3=external-factor
    condition-value: uint,
    permission-change: uint, ;; Bitfield of permissions to add/remove
    escalate: bool, ;; true=add permissions, false=remove permissions
    created-by: principal,
    active: bool
  }
)

;; Cross-chain Permission Mapping
(define-map cross-chain-permissions
  { user: principal, source-chain: (string-ascii 32), target-chain: (string-ascii 32) }
  {
    mapped-permissions: uint,
    mapping-ratio: uint, ;; Percentage of permissions to map (0-100)
    last-sync: uint,
    active: bool
  }
)

;; Variables
(define-data-var next-template-id uint u1)
(define-data-var next-rule-id uint u1)
(define-data-var system-paused bool false)

;; Utility Functions

;; Get user's active templates
(define-read-only (get-user-templates (user principal))
  ;; This would return a list of active template IDs for the user
  ;; Simplified for brevity - in full implementation would query user-template-assignments
  (list)
)

;; Check if permission has expired
(define-read-only (is-permission-expired (expiry (optional uint)))
  (match expiry
    some-expiry (>= block-height some-expiry)
    false)
)

;; Check template-based permissions
(define-private (check-template-permissions
  (user principal)
  (operation uint)
  (value uint))
  (let ((template-assignments (get-user-templates user)))
    ;; Simplified implementation - would iterate through user's templates
    ;; and check if any template grants the required permission
    false
  )
)

;; Custom bitwise operations for Clarity - simplified non-recursive versions
(define-read-only (bit-or (a uint) (b uint))
  ;; Simple addition-based OR approximation for permission combining
  (let ((combined (+ a b)))
    (if (> combined u255) u255 combined)
  )
)

(define-read-only (bit-and (a uint) (b uint))
  ;; Simple modular arithmetic for AND operation
  (if (and (> a u0) (> b u0))
    (mod (* a b) u256)
    u0
  )
)

;; Check if specific permission bit is set using modular arithmetic
(define-read-only (has-permission-bit (permissions uint) (permission-bit uint))
  (>= (mod (/ permissions permission-bit) u2) u1)
)

;; Permission Template Functions

;; Create a new permission template
(define-public (create-permission-template 
  (name (string-ascii 64))
  (permissions uint)
  (threshold uint)
  (duration (optional uint)))
  (let ((template-id (var-get next-template-id)))
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-UNAUTHORIZED)
    (map-set permission-templates
      { template-id: template-id }
      {
        name: name,
        permissions: permissions,
        threshold: threshold,
        duration: duration,
        created-by: tx-sender,
        version: u1,
        active: true
      }
    )
    (var-set next-template-id (+ template-id u1))
    (ok template-id)
  )
)

;; Assign template to user
(define-public (assign-template-to-user 
  (user principal)
  (template-id uint))
  (let ((template (unwrap! (map-get? permission-templates { template-id: template-id }) ERR-TEMPLATE-NOT-FOUND))
        (expiry (match (get duration template)
                  some-duration (some (+ block-height some-duration))
                  none)))
    (asserts! (get active template) ERR-INVALID-TEMPLATE)
    (map-set user-template-assignments
      { user: user, template-id: template-id }
      {
        assigned-at: block-height,
        assigned-by: tx-sender,
        expiry: expiry,
        active: true
      }
    )
    (ok true)
  )
)

;; Granular Permission Functions

;; Grant specific permission to user
(define-public (grant-permission
  (user principal)
  (asset (string-ascii 64))
  (operation uint)
  (threshold uint)
  (duration (optional uint)))
  (let ((expiry (match duration
                  some-duration (some (+ block-height some-duration))
                  none)))
    (map-set user-permissions
      { user: user, asset: asset, operation: operation }
      {
        granted: true,
        threshold: threshold,
        expiry: expiry,
        granted-by: tx-sender,
        granted-at: block-height
      }
    )
    (ok true)
  )
)

;; Revoke specific permission from user
(define-public (revoke-permission
  (user principal)
  (asset (string-ascii 64))
  (operation uint))
  (begin
    (map-delete user-permissions { user: user, asset: asset, operation: operation })
    (ok true)
  )
)

;; Check if user has specific permission
(define-read-only (has-permission
  (user principal)
  (asset (string-ascii 64))
  (operation uint)
  (value uint))
  (let ((direct-permission (map-get? user-permissions { user: user, asset: asset, operation: operation })))
    (match direct-permission
      some-permission 
        (and 
          (get granted some-permission)
          (>= value (get threshold some-permission))
          (match (get expiry some-permission)
            some-expiry (< block-height some-expiry)
            true))
      ;; Check template-based permissions
      (check-template-permissions user operation value)
    )
  )
)

;; Dynamic Permission Functions

;; Create dynamic permission rule
(define-public (create-dynamic-rule
  (name (string-ascii 64))
  (condition-type uint)
  (condition-value uint)
  (permission-change uint)
  (escalate bool))
  (let ((rule-id (var-get next-rule-id)))
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-UNAUTHORIZED)
    (map-set dynamic-permission-rules
      { rule-id: rule-id }
      {
        name: name,
        condition-type: condition-type,
        condition-value: condition-value,
        permission-change: permission-change,
        escalate: escalate,
        created-by: tx-sender,
        active: true
      }
    )
    (var-set next-rule-id (+ rule-id u1))
    (ok rule-id)
  )
)

;; Apply dynamic permission adjustments
(define-public (apply-dynamic-adjustments
  (user principal)
  (asset (string-ascii 64))
  (current-value uint))
  (begin
    ;; This would evaluate all active dynamic rules
    ;; and adjust permissions accordingly
    ;; Simplified implementation
    (ok true)
  )
)

;; Cross-chain Permission Functions

;; Map permissions across chains
(define-public (map-cross-chain-permissions
  (user principal)
  (source-chain (string-ascii 32))
  (target-chain (string-ascii 32))
  (permissions uint)
  (mapping-ratio uint))
  (begin
    (asserts! (<= mapping-ratio u100) ERR-INVALID-PERMISSION)
    (map-set cross-chain-permissions
      { user: user, source-chain: source-chain, target-chain: target-chain }
      {
        mapped-permissions: permissions,
        mapping-ratio: mapping-ratio,
        last-sync: block-height,
        active: true
      }
    )
    (ok true)
  )
)

;; Combine permission bitfields
(define-read-only (combine-permissions (perm1 uint) (perm2 uint))
  (let ((combined (+ perm1 perm2)))
    ;; Ensure we don't exceed maximum permission value
    (if (> combined u255) u255 combined)
  )
)

;; Administrative Functions

;; Update template version
(define-public (update-template-version
  (template-id uint)
  (new-permissions uint)
  (new-threshold uint))
  (let ((template (unwrap! (map-get? permission-templates { template-id: template-id }) ERR-TEMPLATE-NOT-FOUND)))
    (asserts! (is-eq tx-sender (get created-by template)) ERR-UNAUTHORIZED)
    (map-set permission-templates
      { template-id: template-id }
      (merge template {
        permissions: new-permissions,
        threshold: new-threshold,
        version: (+ (get version template) u1)
      })
    )
    (ok true)
  )
)

;; Bulk permission assignment
(define-public (bulk-assign-permissions
  (users (list 50 principal))
  (template-id uint))
  (let ((template (unwrap! (map-get? permission-templates { template-id: template-id }) ERR-TEMPLATE-NOT-FOUND)))
    (asserts! (get active template) ERR-INVALID-TEMPLATE)
    (ok (map assign-template-to-single-user users))
  )
)

;; Helper for bulk assignment
(define-private (assign-template-to-single-user (user principal))
  ;; This would assign the current template to the user
  ;; Implementation would need the template-id from context
  true
)

;; Emergency functions

;; Emergency revoke all permissions for user
(define-public (emergency-revoke-all (user principal))
  (begin
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-UNAUTHORIZED)
    ;; This would iterate through all user permissions and revoke them
    ;; Simplified for brevity
    (ok true)
  )
)

;; Pause/unpause permission system
(define-public (toggle-system-pause)
  (begin
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-UNAUTHORIZED)
    (var-set system-paused (not (var-get system-paused)))
    (ok (var-get system-paused))
  )
)

;; Read-only functions for querying

;; Get permission details
(define-read-only (get-permission-details
  (user principal)
  (asset (string-ascii 64))
  (operation uint))
  (map-get? user-permissions { user: user, asset: asset, operation: operation })
)

;; Get template details
(define-read-only (get-template-details (template-id uint))
  (map-get? permission-templates { template-id: template-id })
)

;; Get cross-chain mapping
(define-read-only (get-cross-chain-mapping
  (user principal)
  (source-chain (string-ascii 32))
  (target-chain (string-ascii 32)))
  (map-get? cross-chain-permissions { user: user, source-chain: source-chain, target-chain: target-chain })
)
