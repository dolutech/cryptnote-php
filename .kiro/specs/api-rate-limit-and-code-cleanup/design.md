# Design Document

## Overview

Este documento descreve a arquitetura técnica para implementação de Rate Limiting na API do CryptNote e refatoração de componentes compartilhados para redução de código duplicado.

## Architecture

### Estrutura de Arquivos

```
cryptnote/
├── config/
│   ├── api.php          # Atualizado com rate limiting
│   ├── components.php   # NOVO - Componentes compartilhados
│   ├── database.php     # Existente
│   ├── i18n.php         # Existente
│   └── security.php     # Existente
├── database/
│   ├── cryptnote.db     # Existente
│   └── ratelimit.db     # NOVO - Storage do rate limiter
├── api/v1/
│   ├── create.php       # Atualizado com rate limit check
│   ├── status.php       # Atualizado com rate limit check
│   └── view.php         # Atualizado com rate limit check
├── index.php            # Refatorado com componentes
├── view.php             # Refatorado com componentes
├── expired.php          # Refatorado com componentes
├── privacy.php          # Refatorado com componentes
└── api-docs.php         # Refatorado + documentação rate limit
```

## Components and Interfaces

### 1. RateLimiter Class (config/api.php)

```php
class RateLimiter {
    private PDO $db;
    private int $maxRequests = 60;
    private int $windowSeconds = 60;
    
    public function __construct();
    public function check(string $ip): array;
    public function getRemainingRequests(string $ip): int;
    public function getResetTime(string $ip): int;
    public function cleanup(): void;
    
    private function getClientIp(): string;
    private function initDatabase(): void;
}
```

**Métodos:**
- `check($ip)`: Verifica se IP pode fazer requisição, retorna `['allowed' => bool, 'remaining' => int, 'reset' => int]`
- `getClientIp()`: Obtém IP real considerando X-Forwarded-For
- `cleanup()`: Remove registros expirados (chamado probabilisticamente)

### 2. Funções de Rate Limit (config/api.php)

```php
function api_check_rate_limit(): void;
function api_set_rate_limit_headers(int $remaining, int $reset): void;
function api_rate_limit_exceeded(int $retryAfter): void;
```

### 3. Componentes Compartilhados (config/components.php)

```php
class Components {
    public static function head(array $options): void;
    public static function navbar(string $currentPage = ''): void;
    public static function footer(): void;
    public static function themeScript(): void;
    public static function toast(): void;
}
```

**Parâmetros de `head()`:**
```php
$options = [
    'title' => 'Page Title',
    'description' => 'Meta description',
    'canonical' => 'https://cryptnote.pro/page.php',
    'robots' => 'index, follow',
    'extra_css' => '',
    'extra_js' => ''
];
```

## Data Models

### Rate Limit Storage (SQLite)

```sql
CREATE TABLE rate_limits (
    ip VARCHAR(45) PRIMARY KEY,
    requests INTEGER DEFAULT 1,
    window_start INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_rate_limits_window ON rate_limits(window_start);
```

**Campos:**
- `ip`: Endereço IP do cliente (suporta IPv6)
- `requests`: Contador de requisições na janela atual
- `window_start`: Unix timestamp do início da janela
- `created_at`: Timestamp de criação do registro

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system.*

### Property 1: Rate Limit Enforcement
*For any* IP address making more than 60 requests within 60 seconds, the 61st request SHALL receive HTTP 429 response.
**Validates: Requirements 1.2**

### Property 2: Rate Limit Headers Consistency
*For any* API response, the X-RateLimit-Remaining header value SHALL equal (60 - number of requests in current window).
**Validates: Requirements 1.3**

### Property 3: Component Visual Equivalence
*For any* page using shared components, the rendered HTML SHALL produce visually identical output to the original implementation.
**Validates: Requirements 6.1**

### Property 4: IP Detection Accuracy
*For any* request with X-Forwarded-For header, the rate limiter SHALL use the first IP in the chain as the client IP.
**Validates: Requirements 1.6**

## Error Handling

### Rate Limiter Errors

| Scenario | Handling |
|----------|----------|
| Database connection fails | Log error, allow request (fail-open) |
| Invalid IP format | Use fallback IP detection |
| Cleanup fails | Log error, continue operation |

### Component Errors

| Scenario | Handling |
|----------|----------|
| Component file missing | PHP fatal error (intentional - critical) |
| Invalid parameters | Use default values |

## Testing Strategy

### Unit Tests (PHP Puro)
1. **test_rate_limiter.php**: Testa classe RateLimiter isoladamente
2. **test_components.php**: Testa renderização de componentes

### Integration Tests
1. Simular múltiplas requisições à API
2. Verificar headers de rate limit
3. Verificar resposta 429 após limite

### Visual Regression
1. Comparar output HTML antes/depois da refatoração
2. Verificar em modo claro e escuro
