# VaultGuardian

**Enterprise-grade blockchain asset access control with fine-grained permissions and hierarchical authorization**

VaultGuardian is a comprehensive access control solution designed for organizations managing blockchain assets at scale. It provides sophisticated permission management, time-bound delegation capabilities, and hierarchical authorization structures while maintaining complete audit trails for regulatory compliance.

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Getting Started](#getting-started)
- [Configuration](#configuration)
- [Permission Management](#permission-management)
- [Role Delegation](#role-delegation)
- [Audit & Compliance](#audit--compliance)
- [API Reference](#api-reference)
- [Security](#security)
- [Deployment](#deployment)
- [Contributing](#contributing)
- [Support](#support)

## Overview

VaultGuardian addresses the critical need for enterprise-level access control in blockchain environments. Traditional blockchain solutions often lack the granular permission structures required by large organizations, leading to security risks and compliance challenges.

### Problem Statement

- **Lack of granular permissions**: Most blockchain solutions operate on binary access models
- **No time-bound access**: Permanent permissions create security vulnerabilities
- **Insufficient audit trails**: Regulatory compliance requires detailed access logging
- **Complex organizational hierarchies**: Enterprise structures need flexible role delegation

### Solution

VaultGuardian provides a sophisticated layer between users and blockchain assets, enabling:
- **Fine-grained access control** down to individual transaction types
- **Temporal permissions** that automatically expire
- **Hierarchical role structures** reflecting organizational charts
- **Comprehensive audit logging** for compliance reporting

## Key Features

### 🔐 Fine-Grained Permissions

**Granular Access Control**
- Transaction-level permissions (read, write, execute, approve)
- Asset-specific restrictions (tokens, NFTs, smart contracts)
- Function-level access for smart contract interactions
- Multi-signature threshold management

**Permission Scopes**
```
├── Asset Level
│   ├── Token Permissions
│   ├── NFT Collections
│   └── Smart Contracts
├── Function Level
│   ├── Transfer Rights
│   ├── Approval Powers
│   └── Administrative Functions
└── Network Level
    ├── Mainnet Access
    ├── Testnet Access
    └── Cross-chain Operations
```

### ⏰ Time-Bound Delegation

**Temporal Access Management**
- Automatic permission expiration
- Scheduled access grants
- Emergency access protocols with auto-revocation
- Recurring permission patterns

**Delegation Features**
- Temporary role elevation
- Project-based access grants
- Vacation/coverage delegation
- Emergency override mechanisms

### 🏢 Hierarchy-Based Authorization

**Organizational Structure Mapping**
- Department-based role inheritance
- Manager-subordinate relationships
- Cross-functional team permissions
- Matrix organization support

**Role Management**
- Predefined role templates
- Custom role creation
- Role composition and inheritance
- Dynamic role assignment

### 📊 Comprehensive Audit Trails

**Compliance-Ready Logging**
- Immutable access logs
- Real-time permission monitoring
- Automated compliance reporting
- Forensic investigation tools

**Audit Features**
- Transaction-level tracking
- Permission change history
- Failed access attempt logging
- Performance analytics

## Architecture

### System Components

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web Interface │    │   Mobile App    │    │   API Gateway   │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                    ┌─────────────┴───────────┐
                    │   VaultGuardian Core    │
                    └─────────────┬───────────┘
                                  │
        ┌─────────────────────────┼─────────────────────────┐
        │                         │                         │
┌───────▼────────┐    ┌───────────▼────────┐    ┌──────────▼─────────┐
│ Permission      │    │ Delegation         │    │ Audit & Compliance │
│ Engine          │    │ Manager            │    │ Module             │
└────────────────┘    └────────────────────┘    └────────────────────┘
        │                         │                         │
        └─────────────────────────┼─────────────────────────┘
                                  │
                    ┌─────────────▼───────────┐
                    │   Blockchain Layer      │
                    │                         │
                    │ ┌─────┐ ┌─────┐ ┌─────┐ │
                    │ │ ETH │ │ BSC │ │ ... │ │
                    │ └─────┘ └─────┘ └─────┘ │
                    └─────────────────────────┘
```

### Technology Stack

**Backend**
- **Runtime**: Node.js / TypeScript
- **Framework**: Express.js with GraphQL
- **Database**: PostgreSQL with Redis caching
- **Blockchain**: Web3.js, Ethers.js
- **Security**: JWT, OAuth 2.0, 2FA

**Frontend**
- **Framework**: React with TypeScript
- **State Management**: Redux Toolkit
- **UI Library**: Material-UI / Ant Design
- **Charts**: Chart.js, D3.js

**Infrastructure**
- **Containerization**: Docker, Kubernetes
- **Cloud**: AWS/GCP/Azure compatible
- **Monitoring**: Prometheus, Grafana
- **Logging**: ELK Stack (Elasticsearch, Logstash, Kibana)

## Getting Started

### Prerequisites

- Node.js 18.x or higher
- PostgreSQL 14.x or higher
- Redis 6.x or higher
- Docker (optional, recommended for development)

### Installation

#### Option 1: Docker Compose (Recommended)

```bash
# Clone the repository
git clone https://github.com/your-org/vaultguardian.git
cd vaultguardian

# Copy environment configuration
cp .env.example .env

# Start all services
docker-compose up -d

# Initialize database
docker-compose exec api npm run db:migrate
docker-compose exec api npm run db:seed
```

#### Option 2: Manual Installation

```bash
# Install dependencies
npm install

# Set up environment variables
cp .env.example .env
# Edit .env with your configuration

# Set up database
createdb vaultguardian
npm run db:migrate
npm run db:seed

# Start Redis
redis-server

# Start the application
npm run dev
```

### Initial Configuration

1. **Access the application**: http://localhost:3000
2. **Default admin credentials**:
   - Username: `admin@vaultguardian.com`
   - Password: `temp-admin-password`
3. **Complete setup wizard**:
   - Change admin password
   - Configure blockchain networks
   - Set up organizational structure
   - Configure notification settings

## Configuration

### Environment Variables

```bash
# Application
NODE_ENV=development
PORT=3000
APP_SECRET=your-super-secret-key

# Database
DATABASE_URL=postgresql://username:password@localhost:5432/vaultguardian
REDIS_URL=redis://localhost:6379

# Blockchain Networks
ETHEREUM_RPC_URL=https://mainnet.infura.io/v3/your-project-id
POLYGON_RPC_URL=https://polygon-rpc.com
BSC_RPC_URL=https://bsc-dataseed1.binance.org

# Security
JWT_SECRET=your-jwt-secret
ENCRYPTION_KEY=your-32-character-encryption-key
SESSION_TIMEOUT=3600

# Email Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password

# Audit & Compliance
AUDIT_RETENTION_DAYS=2555  # 7 years
COMPLIANCE_MODE=SOX,GDPR,PCI-DSS
```

### Network Configuration

```yaml
# config/networks.yml
networks:
  ethereum:
    name: "Ethereum Mainnet"
    chainId: 1
    rpcUrl: ${ETHEREUM_RPC_URL}
    blockExplorer: "https://etherscan.io"
    gasPrice: "auto"
    
  polygon:
    name: "Polygon"
    chainId: 137
    rpcUrl: ${POLYGON_RPC_URL}
    blockExplorer: "https://polygonscan.com"
    gasPrice: "30"
    
  bsc:
    name: "Binance Smart Chain"
    chainId: 56
    rpcUrl: ${BSC_RPC_URL}
    blockExplorer: "https://bscscan.com"
    gasPrice: "5"
```

## Permission Management

### Permission Types

VaultGuardian supports four primary permission levels:

1. **READ**: View balances, transaction history, and asset details
2. **WRITE**: Initiate transactions (requires approval)
3. **EXECUTE**: Execute approved transactions
4. **APPROVE**: Approve pending transactions from other users

### Creating Permissions

#### Via Web Interface

1. Navigate to **Permissions** > **Create New**
2. Select user or role
3. Choose assets and functions
4. Set time bounds (optional)
5. Add approval requirements
6. Save and activate

#### Via API

```javascript
const permission = await vaultGuardian.permissions.create({
  grantee: {
    type: 'user',
    id: 'user-123'
  },
  resources: [
    {
      type: 'token',
      address: '0x...',
      network: 'ethereum',
      functions: ['transfer', 'approve']
    }
  ],
  conditions: {
    maxAmount: '1000',
    timeLimit: {
      start: '2024-01-01T00:00:00Z',
      end: '2024-12-31T23:59:59Z'
    },
    approvalRequired: true,
    approvers: ['manager-456']
  }
});
```

### Permission Templates

Pre-configured permission sets for common roles:

**Treasury Manager**
- Full access to treasury assets
- Unlimited transaction amounts
- Can delegate permissions
- Requires dual approval for transfers > $100k

**Finance Analyst**
- Read-only access to all assets
- Export transaction reports
- View real-time balances
- Generate compliance reports

**Project Lead**
- Project-specific asset access
- Limited delegation rights
- Time-bound permissions
- Transaction limits based on project budget

## Role Delegation

### Delegation Types

#### Temporary Elevation
Grant higher-level permissions for a specific time period:

```javascript
await vaultGuardian.delegation.createTemporary({
  delegator: 'manager-123',
  delegate: 'employee-456',
  role: 'senior-analyst',
  duration: '7d',
  reason: 'Quarterly reporting period'
});
```

#### Project-Based Access
Grant permissions specific to project needs:

```javascript
await vaultGuardian.delegation.createProject({
  project: 'defi-integration-q1',
  members: ['dev-789', 'qa-012'],
  permissions: ['testnet-deploy', 'contract-interact'],
  budget: {
    amount: '50000',
    token: 'USDC'
  },
  timeline: {
    start: '2024-01-15',
    end: '2024-03-31'
  }
});
```

#### Emergency Access
Provide immediate access with automatic audit alerts:

```javascript
await vaultGuardian.delegation.createEmergency({
  delegate: 'incident-responder-345',
  scope: 'security-incident-2024-001',
  maxDuration: '24h',
  autoRevoke: true,
  notifications: ['security-team', 'c-level']
});
```

### Delegation Workflows

**Standard Delegation Process**
1. Delegator initiates request
2. System validates delegator authority
3. Delegate receives notification
4. Delegate accepts delegation
5. Permissions activate automatically
6. Audit trail records all actions

**Approval-Required Delegation**
1. Employee requests elevated access
2. Manager reviews and approves
3. HR/Compliance validates (if required)
4. System grants temporary permissions
5. Automatic expiration and cleanup

## Audit & Compliance

### Audit Trail Features

**Immutable Logging**
- All permission changes logged
- Cryptographic signatures on log entries
- Tamper-evident audit records
- Blockchain anchoring for critical events

**Real-time Monitoring**
- Live dashboard of access events
- Anomaly detection algorithms
- Automatic alert generation
- Integration with SIEM systems

### Compliance Reporting

**Pre-built Reports**
- SOX compliance reports
- GDPR data access logs
- PCI-DSS audit trails
- Custom regulatory frameworks

**Automated Compliance**
```javascript
// Schedule automated compliance reports
await vaultGuardian.compliance.scheduleReport({
  type: 'SOX_QUARTERLY',
  recipients: ['audit@company.com'],
  schedule: '0 0 1 */3 *', // First day of every quarter
  format: 'PDF',
  encryption: true
});
```

### Data Retention

**Configurable Retention Policies**
- Audit logs: 7 years (configurable)
- Transaction records: 10 years
- Access logs: 3 years
- System logs: 1 year

**GDPR Compliance**
- Right to be forgotten implementation
- Data portability features
- Consent management tracking
- Cross-border data transfer logs

## API Reference

### Authentication

All API requests require authentication via JWT tokens:

```bash
# Get access token
curl -X POST https://api.vaultguardian.com/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@company.com",
    "password": "password",
    "mfaCode": "123456"
  }'

# Use token in subsequent requests
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  https://api.vaultguardian.com/api/v1/permissions
```

### Core Endpoints

#### Permissions API

```bash
# List permissions
GET /api/v1/permissions

# Create permission
POST /api/v1/permissions
{
  "grantee": "user-123",
  "resource": "token:0x...",
  "actions": ["read", "write"],
  "conditions": {
    "timeLimit": "2024-12-31T00:00:00Z",
    "maxAmount": "1000"
  }
}

# Update permission
PUT /api/v1/permissions/:id

# Revoke permission
DELETE /api/v1/permissions/:id
```

#### Delegation API

```bash
# Create delegation
POST /api/v1/delegations
{
  "delegate": "user-456",
  "role": "analyst",
  "duration": "7d",
  "reason": "Project coverage"
}

# List active delegations
GET /api/v1/delegations?status=active

# Revoke delegation
DELETE /api/v1/delegations/:id
```

#### Audit API

```bash
# Get audit logs
GET /api/v1/audit/logs?from=2024-01-01&to=2024-01-31

# Export compliance report
POST /api/v1/audit/reports
{
  "type": "SOX_QUARTERLY",
  "period": "2024-Q1",
  "format": "PDF"
}
```

### WebSocket Events

Real-time updates via WebSocket connection:

```javascript
const ws = new WebSocket('wss://api.vaultguardian.com/ws');

ws.on('permission.granted', (event) => {
  console.log('New permission granted:', event);
});

ws.on('transaction.pending', (event) => {
  console.log('Transaction requires approval:', event);
});

ws.on('security.alert', (event) => {
  console.log('Security alert:', event);
});
```

## Security

### Security Architecture

**Multi-layered Security**
- Application-level access controls
- Database encryption at rest
- TLS encryption in transit
- Hardware security module (HSM) integration

**Authentication & Authorization**
- Multi-factor authentication (MFA)
- Single sign-on (SSO) integration
- OAuth 2.0 / OpenID Connect
- Role-based access control (RBAC)

### Key Management

**Hierarchical Deterministic (HD) Wallets**
- BIP32/BIP44 compliant key derivation
- Hardware wallet integration
- Multi-signature wallet support
- Key rotation policies

**Secure Key Storage**
- HSM integration for production
- Encrypted key storage
- Distributed key management
- Regular key audits

### Security Best Practices

**Operational Security**
- Regular security assessments
- Penetration testing
- Code security reviews
- Vulnerability management

**Compliance**
- ISO 27001 framework alignment
- SOC 2 Type II controls
- Regular compliance audits
- Third-party security certifications

## Deployment

### Production Deployment

#### Kubernetes Deployment

```yaml
# k8s/vaultguardian-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vaultguardian-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: vaultguardian-api
  template:
    metadata:
      labels:
        app: vaultguardian-api
    spec:
      containers:
      - name: api
        image: vaultguardian/api:latest
        ports:
        - containerPort: 3000
        env:
        - name: NODE_ENV
          value: "production"
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: vaultguardian-secrets
              key: database-url
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
```

#### Docker Compose for Production

```yaml
version: '3.8'
services:
  api:
    image: vaultguardian/api:latest
    environment:
      - NODE_ENV=production
      - DATABASE_URL=${DATABASE_URL}
    ports:
      - "3000:3000"
    depends_on:
      - db
      - redis
    restart: unless-stopped
    
  frontend:
    image: vaultguardian/frontend:latest
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./ssl:/etc/ssl/certs
    restart: unless-stopped
    
  db:
    image: postgres:14
    environment:
      - POSTGRES_DB=vaultguardian
      - POSTGRES_USER=${DB_USER}
      - POSTGRES_PASSWORD=${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped
    
  redis:
    image: redis:6-alpine
    restart: unless-stopped

volumes:
  postgres_data:
```

### Monitoring & Alerting

**Health Checks**
```bash
# API health check
curl https://api.vaultguardian.com/health

# Database health check
curl https://api.vaultguardian.com/health/db

# Blockchain connectivity check
curl https://api.vaultguardian.com/health/blockchain
```

**Prometheus Metrics**
- Request latency and throughput
- Database connection pool status
- Permission grant/revoke rates
- Failed authentication attempts
- Blockchain transaction success rates

### Backup & Recovery

**Database Backups**
- Automated daily backups
- Point-in-time recovery capability
- Cross-region backup replication
- Encrypted backup storage

**Disaster Recovery**
- RTO: 4 hours
- RPO: 1 hour
- Multi-region deployment support
- Automated failover procedures

## Contributing

We welcome contributions to VaultGuardian! Please read our contributing guidelines before submitting pull requests.

### Development Setup

```bash
# Fork and clone the repository
git clone https://github.com/yourusername/vaultguardian.git
cd vaultguardian

# Install dependencies
npm install

# Set up pre-commit hooks
npm run prepare

# Start development environment
npm run dev:docker
```

### Code Standards

- **Language**: TypeScript for all new code
- **Linting**: ESLint with Prettier
- **Testing**: Jest with >90% coverage requirement
- **Documentation**: JSDoc comments for all public APIs

### Pull Request Process

1. Create feature branch from `develop`
2. Implement changes with tests
3. Update documentation
4. Run full test suite
5. Submit PR with detailed description
6. Address review feedback
7. Merge after approval

### Security Vulnerability Reporting

Please report security vulnerabilities privately to security@vaultguardian.com. Do not create public GitHub issues for security concerns.

## Support

### Documentation
- **API Docs**: https://docs.vaultguardian.com
- **User Guide**: https://help.vaultguardian.com
- **Video Tutorials**: https://tutorials.vaultguardian.com

### Community
- **Discord**: https://discord.gg/vaultguardian
- **Forum**: https://forum.vaultguardian.com
- **Stack Overflow**: Tag questions with `vaultguardian`

### Enterprise Support
- **Email**: enterprise@vaultguardian.com
- **Phone**: +1-800-VAULT-GD
- **Support Portal**: https://support.vaultguardian.com

### License

VaultGuardian is licensed under the MIT License. See [LICENSE](LICENSE) file for details.

---

**VaultGuardian** - Securing blockchain assets for the enterprise