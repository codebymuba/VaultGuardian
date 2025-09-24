;; Granular Permission Framework
;; Implements asset-specific permissions, operation-level permissions,
;; value-based thresholds, and cross-chain permission mapping

;; Error codes
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-INVALID-PERMISSION (err u101))
(define-constant ERR-THRESHOLD-EXCEEDED (err u102))
(define-constant ERR-INVALID-CHAIN (err u103))

;; Permission types
(define-constant PERMISSION-TRANSFER u1)
(define-constant PERMISSION-APPROVE u2)
(define-constant PERMISSION-BURN u3)
(define-constant PERMISSION-MINT u4)

;; Operation levels
(define-constant OPERATION-READ u1)
(define-constant OPERATION-WRITE u2)
(define-constant OPERATION-EXECUTE u3)
(define-constant OPERATION-DELEGATE u4)

;; Data maps for storing permissions
(define-map asset-permissions 
  { asset-id: (string-ascii 64), principal: principal, permission-type: uint } 
  { allowed: bool })

(define-map operation-permissions 
  { principal: principal, operation-type: uint } 
  { allowed: bool })

(define-map value-thresholds 
  { principal: principal, permission-type: uint } 
  { threshold: uint })

(define-map cross-chain-permissions 
  { chain-id: (string-ascii 32), external-address: (string-ascii 64), permission-type: uint } 
  { stacks-principal: principal, allowed: bool })

;; Admin principal
(define-data-var contract-admin principal tx-sender)

;; Check if caller is admin
(define-private (is-admin)
  (is-eq tx-sender (var-get contract-admin)))

;; Set a new admin
(define-public (set-admin (new-admin principal))
  (begin
    (asserts! (is-admin) ERR-NOT-AUTHORIZED)
    (ok (var-set contract-admin new-admin))))

;; Asset-specific permission functions
(define-public (set-asset-permission (asset-id (string-ascii 64)) (user principal) (permission-type uint) (allowed bool))
  (begin
    (asserts! (is-admin) ERR-NOT-AUTHORIZED)
    (asserts! (is-valid-permission-type permission-type) ERR-INVALID-PERMISSION)
    (ok (map-set asset-permissions { asset-id: asset-id, principal: user, permission-type: permission-type } { allowed: allowed }))))

(define-read-only (check-asset-permission (asset-id (string-ascii 64)) (user principal) (permission-type uint))
  (default-to false (get allowed (map-get? asset-permissions { asset-id: asset-id, principal: user, permission-type: permission-type }))))

;; Operation-level permission functions
(define-public (set-operation-permission (user principal) (operation-type uint) (allowed bool))
  (begin
    (asserts! (is-admin) ERR-NOT-AUTHORIZED)
    (asserts! (is-valid-operation-type operation-type) ERR-INVALID-PERMISSION)
    (ok (map-set operation-permissions { principal: user, operation-type: operation-type } { allowed: allowed }))))

(define-read-only (check-operation-permission (user principal) (operation-type uint))
  (default-to false (get allowed (map-get? operation-permissions { principal: user, operation-type: operation-type }))))

;; Value threshold functions
(define-public (set-value-threshold (user principal) (permission-type uint) (threshold uint))
  (begin
    (asserts! (is-admin) ERR-NOT-AUTHORIZED)
    (asserts! (is-valid-permission-type permission-type) ERR-INVALID-PERMISSION)
    (ok (map-set value-thresholds { principal: user, permission-type: permission-type } { threshold: threshold }))))

(define-read-only (check-value-threshold (user principal) (permission-type uint) (value uint))
  (let ((threshold (default-to u0 (get threshold (map-get? value-thresholds { principal: user, permission-type: permission-type })))))
    (<= value threshold)))

;; Cross-chain permission mapping
(define-public (set-cross-chain-permission 
                (chain-id (string-ascii 32)) 
                (external-address (string-ascii 64)) 
                (permission-type uint) 
                (stacks-principal principal) 
                (allowed bool))
  (begin
    (asserts! (is-admin) ERR-NOT-AUTHORIZED)
    (asserts! (is-valid-permission-type permission-type) ERR-INVALID-PERMISSION)
    (ok (map-set cross-chain-permissions 
                { chain-id: chain-id, external-address: external-address, permission-type: permission-type } 
                { stacks-principal: stacks-principal, allowed: allowed }))))

(define-read-only (check-cross-chain-permission 
                   (chain-id (string-ascii 32)) 
                   (external-address (string-ascii 64)) 
                   (permission-type uint))
  (default-to 
    { stacks-principal: tx-sender, allowed: false } 
    (map-get? cross-chain-permissions { chain-id: chain-id, external-address: external-address, permission-type: permission-type })))

;; Helper functions to validate permission and operation types
(define-private (is-valid-permission-type (permission-type uint))
  (or 
    (is-eq permission-type PERMISSION-TRANSFER)
    (is-eq permission-type PERMISSION-APPROVE)
    (is-eq permission-type PERMISSION-BURN)
    (is-eq permission-type PERMISSION-MINT)))

(define-private (is-valid-operation-type (operation-type uint))
  (or 
    (is-eq operation-type OPERATION-READ)
    (is-eq operation-type OPERATION-WRITE)
    (is-eq operation-type OPERATION-EXECUTE)
    (is-eq operation-type OPERATION-DELEGATE)))

;; Example asset operation functions that use the permission framework
(define-public (transfer-asset (asset-id (string-ascii 64)) (recipient principal) (amount uint))
  (begin
    (asserts! (check-asset-permission asset-id tx-sender PERMISSION-TRANSFER) ERR-NOT-AUTHORIZED)
    (asserts! (check-operation-permission tx-sender OPERATION-WRITE) ERR-NOT-AUTHORIZED)
    (asserts! (check-value-threshold tx-sender PERMISSION-TRANSFER amount) ERR-THRESHOLD-EXCEEDED)
    ;; Actual transfer logic would go here
    (ok true)))

(define-public (mint-asset (asset-id (string-ascii 64)) (recipient principal) (amount uint))
  (begin
    (asserts! (check-asset-permission asset-id tx-sender PERMISSION-MINT) ERR-NOT-AUTHORIZED)
    (asserts! (check-operation-permission tx-sender OPERATION-EXECUTE) ERR-NOT-AUTHORIZED)
    (asserts! (check-value-threshold tx-sender PERMISSION-MINT amount) ERR-THRESHOLD-EXCEEDED)
    ;; Actual minting logic would go here
    (ok true)))

(define-public (burn-asset (asset-id (string-ascii 64)) (amount uint))
  (begin
    (asserts! (check-asset-permission asset-id tx-sender PERMISSION-BURN) ERR-NOT-AUTHORIZED)
    (asserts! (check-operation-permission tx-sender OPERATION-EXECUTE) ERR-NOT-AUTHORIZED)
    (asserts! (check-value-threshold tx-sender PERMISSION-BURN amount) ERR-THRESHOLD-EXCEEDED)
    ;; Actual burning logic would go here
    (ok true)))

(define-public (approve-asset-operator (asset-id (string-ascii 64)) (operator principal))
  (begin
    (asserts! (check-asset-permission asset-id tx-sender PERMISSION-APPROVE) ERR-NOT-AUTHORIZED)
    (asserts! (check-operation-permission tx-sender OPERATION-DELEGATE) ERR-NOT-AUTHORIZED)
    ;; Actual approval logic would go here
    (ok true)))

;; Cross-chain operation example
(define-public (execute-cross-chain-operation 
                (chain-id (string-ascii 32)) 
                (external-address (string-ascii 64)) 
                (permission-type uint))
  (let ((permission-data (check-cross-chain-permission chain-id external-address permission-type)))
    (begin
      (asserts! (get allowed permission-data) ERR-NOT-AUTHORIZED)
      ;; Cross-chain operation logic would go here
      (ok true))))