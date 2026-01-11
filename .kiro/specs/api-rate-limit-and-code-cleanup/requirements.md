# Requirements Document

## Introduction

Este documento especifica os requisitos para implementação de Rate Limiting na API pública do CryptNote e redução de código duplicado no projeto. O objetivo é proteger a API contra abuso mantendo-a acessível publicamente, e melhorar a manutenibilidade do código sem afetar funcionalidades existentes.

## Glossary

- **Rate_Limiter**: Sistema que controla o número de requisições permitidas por IP em um período de tempo
- **API_Endpoint**: Ponto de acesso da API REST do CryptNote (/api/v1/*)
- **Shared_Components**: Arquivos PHP reutilizáveis contendo código comum entre páginas
- **IP_Address**: Endereço de rede do cliente que faz a requisição

## Requirements

### Requirement 1: Rate Limiting na API

**User Story:** As a system administrator, I want to limit API requests per IP address, so that the public API is protected against abuse while remaining accessible to legitimate users.

#### Acceptance Criteria

1. WHEN a client makes API requests, THE Rate_Limiter SHALL track the number of requests per IP address
2. WHEN a client exceeds 60 requests within 1 minute, THE Rate_Limiter SHALL return HTTP 429 (Too Many Requests) with a JSON error response
3. THE Rate_Limiter SHALL include headers informing the client about rate limit status:
   - `X-RateLimit-Limit`: Maximum requests allowed (60)
   - `X-RateLimit-Remaining`: Requests remaining in current window
   - `X-RateLimit-Reset`: Unix timestamp when the limit resets
4. WHEN rate limit is exceeded, THE API_Endpoint SHALL return a response with `retry_after` field indicating seconds until reset
5. THE Rate_Limiter SHALL use file-based storage compatible with SQLite environment (no Redis/Memcached dependency)
6. THE Rate_Limiter SHALL handle proxy headers (X-Forwarded-For) to identify real client IP behind reverse proxies
7. THE Rate_Limiter SHALL automatically clean up expired rate limit records to prevent storage bloat

### Requirement 2: Shared HTML Head Component

**User Story:** As a developer, I want to have a single source for common HTML head elements, so that I can maintain consistent styling and reduce code duplication across pages.

#### Acceptance Criteria

1. THE Shared_Components SHALL provide a function to render common HTML head elements including:
   - Meta charset and viewport
   - Tailwind CSS CDN link
   - Font Awesome CDN link
   - Google Fonts import
   - Dark mode initialization script
   - Common CSS styles (gradients, glass effect, animations)
2. WHEN a page includes the shared head component, THE page SHALL maintain identical visual appearance to current implementation
3. THE Shared_Components SHALL accept parameters for:
   - Page title
   - Meta description
   - Canonical URL (optional)
   - Additional meta tags (optional)
   - robots directive (optional, default: "index, follow")

### Requirement 3: Shared Navbar Component

**User Story:** As a developer, I want to have a reusable navbar component, so that navigation is consistent across all pages and easier to maintain.

#### Acceptance Criteria

1. THE Shared_Components SHALL provide a function to render the navbar with:
   - Logo and brand name linking to index.php
   - Language switcher (PT/EN)
   - Theme toggle button
   - Mobile menu button and dropdown
2. WHEN the navbar is rendered, THE component SHALL highlight the current page in navigation
3. THE Shared_Components SHALL accept a parameter to indicate the current page for active state styling

### Requirement 4: Shared Footer Component

**User Story:** As a developer, I want to have a reusable footer component, so that footer content is consistent and maintainable.

#### Acceptance Criteria

1. THE Shared_Components SHALL provide a function to render the footer with:
   - Brand section with logo and description
   - Navigation links
   - Security badges
   - Copyright and credits
2. WHEN the footer is rendered, THE component SHALL use the current language for all text

### Requirement 5: Shared Theme Script Component

**User Story:** As a developer, I want to have a reusable theme toggle script, so that dark mode functionality is consistent across pages.

#### Acceptance Criteria

1. THE Shared_Components SHALL provide a function to render the theme toggle JavaScript
2. THE script SHALL handle localStorage persistence of theme preference
3. THE script SHALL work with the navbar theme toggle button

### Requirement 6: Backward Compatibility

**User Story:** As a user, I want all existing functionality to work exactly as before, so that the refactoring does not break my experience.

#### Acceptance Criteria

1. WHEN pages are refactored to use shared components, THE visual appearance SHALL be identical to the original
2. WHEN pages are refactored, THE functionality (forms, buttons, links) SHALL work identically
3. WHEN the API rate limiter is added, THE existing API responses SHALL maintain the same structure for successful requests
4. IF any component fails to load, THEN THE page SHALL gracefully degrade without breaking core functionality

### Requirement 7: API Documentation Update

**User Story:** As an API consumer, I want to know about rate limiting, so that I can implement proper retry logic in my applications.

#### Acceptance Criteria

1. WHEN rate limiting is implemented, THE api-docs.php page SHALL document:
   - Rate limit of 60 requests per minute per IP
   - Rate limit headers returned
   - HTTP 429 response format
   - Recommended retry strategy
