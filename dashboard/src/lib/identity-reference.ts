// Reference data for the six identities deluluscan scans with (see
// scripts/provision_users.py and config.ci.yaml in the target/deluluscan). Surfaced in
// the dashboard so a human reviewing a finding's evidence can immediately see
// what role/permissions/API access the identity that reproduced it actually
// has in the target — e.g. "was this really an anonymous bypass, or did the
// 'readonly' account just have more access than its name implies?"
//
// Kept honest about a real gap in the current provisioning: backend,
// readonly, and api_user are all assigned the identical role today
// (only content_editor gets an additional role, admin is the superuser) —
// the distinct names signal scan *intent*, not an actually-enforced
// permission tier. Don't let the dashboard imply a distinction that doesn't
// exist in the target yet.

export interface IdentityInfo {
  key: string;
  label: string;
  description: string;
  productRoles: string[];
  apiAccess: string;
  notes?: string;
}

export const IDENTITY_REFERENCE: Record<string, IdentityInfo> = {
  anonymous: {
    key: 'anonymous',
    label: 'Anonymous',
    description: 'No credentials at all — represents an unauthenticated internet visitor.',
    productRoles: [],
    apiAccess: 'None — no session, no token, no Authorization header sent.',
  },
  admin: {
    key: 'admin',
    label: 'Admin',
    description: 'the Administrator — the ground-truth oracle every other identity is compared against.',
    productRoles: ['CMS Administrator'],
    apiAccess: 'Full backend + REST API access via Basic auth (internal userId appuser).',
  },
  backend: {
    key: 'backend',
    label: 'Backend',
    description: 'Authenticated back-end user with limited (non-admin) rights.',
    productRoles: ['Back-end User (TARGET_BACK_END_USER)'],
    apiAccess: 'REST API access via Basic auth (backend@example.com).',
  },
  content_editor: {
    key: 'content_editor',
    label: 'Content Editor',
    description: 'Back-end user additionally granted content-editing workflow permissions.',
    productRoles: ['Back-end User (TARGET_BACK_END_USER)', 'Anyone who can Edit Content'],
    apiAccess: 'REST API access via Basic auth (editor@example.com).',
  },
  readonly: {
    key: 'readonly',
    label: 'Read Only',
    description: 'Intended to represent a minimal-permission user.',
    productRoles: ['Back-end User (TARGET_BACK_END_USER)'],
    apiAccess: 'REST API access via Basic auth (readonly@example.com).',
    notes:
      'Currently provisioned with the SAME role as "backend" — the name signals scan intent, but no additional restriction is actually enforced today. Treat a finding exploited by "readonly" as equivalent to "backend" unless you separately confirm a tighter role in the target.',
  },
  api_user: {
    key: 'api_user',
    label: 'API User',
    description: 'Intended to represent a token/API-based consumer.',
    productRoles: ['Back-end User (TARGET_BACK_END_USER)'],
    apiAccess: 'REST API access via Basic auth (apiuser@example.com) — not currently a distinct bearer-token identity.',
    notes:
      'Currently provisioned identically to "backend" (same role, same Basic-auth mechanism, not an actual API token). deluluscan\'s config supports a bearer_token field per identity if a true token-based distinction is needed later.',
  },
};

export const IDENTITY_ORDER = ['anonymous', 'readonly', 'api_user', 'backend', 'content_editor', 'admin'];
