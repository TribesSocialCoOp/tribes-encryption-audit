-- ============================================================
-- Tribes.app Encryption Audit - Test Schema & Seed Data
-- ============================================================
--
-- This schema and data were extracted directly from the Tribes.app
-- development database. The encrypted blobs are real ciphertext
-- produced by the browser's Web Crypto API (AES-256-GCM).
--
-- The original plaintext for these posts was:
--
--   Post 1 (test-service-admin):
--     "TOP SECRET ENCRYPTION TEST: The launch code is ALPHA-BRAVO-7749.
--      If you can read this from the database, encryption is broken."
--
--   Post 2 (test-service-admin):
--     "TOP SECRET ENCRYPTION TEST: The launch code is ALPHA-BRAVO-7749.
--      If you can read this from the database, encryption is broken."
--
--   Post 3 (test-service-member):
--     "MEMBER SECRET: My social security number is 555-12-3456
--      and my bank PIN is 9921. This should be encrypted."
--
-- If you can recover any of those strings from the data below,
-- our encryption is broken. We don't think you can.
--
-- Usage:
--   createdb tribes_audit
--   psql tribes_audit < schema-and-seed.sql
--   npx tsx attack-test.ts
-- ============================================================


-- ── Schema (extracted from Tribes.app dev database) ──────────

CREATE TABLE users (
  id text NOT NULL PRIMARY KEY,
  name text NOT NULL,
  email text,
  role text NOT NULL DEFAULT 'Human_Free',
  bio text,
  avatar text,
  reserved_alias text,
  reserved_alias_avatar text,
  reputation_score integer DEFAULT 0,
  reputation_status text DEFAULT 'Newcomer',
  email_verified boolean DEFAULT false,
  totp_secret text,
  totp_enabled boolean DEFAULT false,
  ai_data_sharing_enabled boolean DEFAULT true,
  is_verified boolean DEFAULT false,
  deletion_requested_at timestamptz,
  created_at timestamptz,
  tos_accepted_version text,
  has_pii_access boolean DEFAULT false,
  encryption_public_key text,
  age_confirmed_at timestamptz
);

CREATE TABLE posts (
  id text NOT NULL PRIMARY KEY,
  tribe_id text,
  author_id text NOT NULL,
  author_name text NOT NULL DEFAULT '',
  author_avatar text,
  author_avatar_fallback text NOT NULL DEFAULT '??',
  title text,
  content text NOT NULL,
  image_url text,
  image_urls jsonb,
  image_alt text,
  data_ai_hint_avatar text,
  data_ai_hint_image text,
  vibe_count integer DEFAULT 0,
  comment_count integer DEFAULT 0,
  is_removed boolean DEFAULT false,
  can_be_reposted boolean DEFAULT true,
  removal_reason text,
  original_post_id text,
  is_pinned boolean DEFAULT false,
  mood_visibility text DEFAULT 'public',
  ring text DEFAULT 'tribes',
  mood_tag text,
  pinned_to_wall boolean DEFAULT false,
  ciphertext bytea,
  is_encrypted boolean DEFAULT false,
  encryption_iv text,
  edited_at timestamptz,
  created_at timestamptz,
  link_url text,
  link_title text,
  link_description text,
  link_image text,
  link_site_name text
);

CREATE TABLE tribe_keys (
  id text NOT NULL PRIMARY KEY,
  tribe_id text NOT NULL,
  key_version integer NOT NULL DEFAULT 1,
  is_active boolean NOT NULL DEFAULT true,
  created_by text NOT NULL,
  created_at timestamptz DEFAULT now(),
  rotated_at timestamptz
);

CREATE TABLE tribe_key_grants (
  id text NOT NULL PRIMARY KEY,
  tribe_key_id text NOT NULL,
  recipient_id text NOT NULL,
  wrapped_key text NOT NULL,
  wrap_iv text NOT NULL,
  granted_by text NOT NULL,
  granted_at timestamptz DEFAULT now()
);

CREATE TABLE vault_backups (
  id text NOT NULL PRIMARY KEY,
  user_id text NOT NULL,
  encrypted_vault bytea NOT NULL,
  salt text NOT NULL,
  created_at timestamptz DEFAULT now()
);


-- ── Seed Data (real encrypted blobs from dev) ────────────────

-- Users who created the encrypted posts
INSERT INTO users (id, name, encryption_public_key) VALUES
  ('test-service-admin', 'Test Service Admin', NULL),
  ('test-service-member', 'Test Service Member', NULL),
  ('dustin', 'Dustin Moore', NULL);

-- Tribe symmetric key metadata (the raw AES key is NEVER stored server-side)
INSERT INTO tribe_keys (id, tribe_id, key_version, is_active, created_by, created_at) VALUES
  ('tk-3-1777839233337', '3', 1, true, 'test-service-admin', '2026-05-03T20:13:53.337Z');

-- RSA-OAEP wrapped copies of the tribe key (one per member)
-- Each wrapped_key is the AES tribe key encrypted with the recipient's RSA-4096 public key.
-- Without the recipient's RSA private key (stored only in their browser), these are opaque blobs.
INSERT INTO tribe_key_grants (id, tribe_key_id, recipient_id, wrapped_key, wrap_iv, granted_by, granted_at) VALUES
  ('tkg-dustin-1777839233472', 'tk-3-1777839233337', 'dustin',
   'rQCWyBjaK6zdiJwcoh81Ydhu1xpuBmlAPpBhaR5wfmzRKayqSJ2EH7gS5NvoRQkV+HbG8O1vLo7ZEa2pNrmvRUuW5gaEqbpjuIVhGxRnhA3n5Hg9W8HUsrJnvNX1aeZwD9oaUSN/njAB6SFTl+EtpmgaU0+qzjPtE+szP/RQlT57brojq7alS3VdfzBIoXOuizwX5ReVcIltjhvnNyQzBDsFGer7jhildv0FEx4H/x3MZd2tmLzyekvwY7fppqDMmGf+oGxbOm1hBEUjtNKyzklm8sg/leLfZRnntH8fFC9CG6h5RXjcttL6a1U1L/90eZIZKVsFpwTwQs4tWtGBWOqdk8OLuMp41rY7kbIn0jUvp0VJ41Jz/R4jjraG6FE3ns0w45PmDfdQ/CChsLmK+UPFKidSvInLSg5Daz8e5SoH5VugKbseIAWlupbBsE6emVQPC7zPGS4Kfo6/eXz6XlXhpVX+qMMk2/egyCagSvQCrmCBLAUVw2S2ae1wZQXwV4ffdNI+CyNHd5qpI0pZ5TLh1W2NdOKBIOPc1BJfQM1/ZERpCepKdC1kw7qIZPZGDdUzbgZenYJp1lJpuKXz2oVeyqk7NZ8GIzHjukkOJUZgO1aH5LFUjqG/ML0xReMCYhzRK231TT48V9v13BGSz36FPllqwtK+AHABDV/Oask=',
   'none', 'test-service-admin', '2026-05-03T20:13:53.472Z'),

  ('tkg-test-ser-1777842949097', 'tk-3-1777839233337', 'test-service-member',
   'YBegdoEglG+LvFu0C/Yc663+9HuWbf974ItGb0lUIo8hGiIKCug+6rFJeQY/QYjlUrNplkiKwWyo+sYNjDTlRfveiOD97xC3DDlHmciN8jT9Fzc+nvJJuxEo1m5qGOFC7C+gtMsY3sg+M0LfgM1jiMY/68hFHkmT49PxWRvZkN1JRkfo+2d/9yuCm/I8M8SiBAjwxdCwaS5B0FZyYFNMYUg7Gs6R7LDU+6wrxGQ8otIH0W6+b7p4SEiIzlDokiLtihjD16zxxrcVxq8kxC2Kr4gZO76tlEBAqAQ1MIYwcP5xJCd9ObE5NQXBGXukfc+o3h9EvynJR4Y3X2UJ+UFOIMogTlXGrgqf3dlDHUr2naYBnLPZ/Azwbg472lFM8BuGxGC68Q0DO9VKDF3B5LzzzcMJSehmpj67pBx9y0ijFlYmQO8HR66W0DkbeGrnydKQ3m4Ll/DVwWmA1wFxEh7svJs3Gkp1Qp9/XnvZRmuDtshoB/riTFWy8/HP/psYubEbrNUO+BYqTsuvbXDIskBBqZmu0REW1f8PFEOM0B9V7MQ4X+fOvyvFU2+DQfFLFXdzg/dVrMlMRNQwbCIAPCIPl5iUj7eDHjltgnX13Qt9MTG9uIGO26XnaxFa85uEk/48RFgkUyYVuKAlvgIj77lm88pNkge1i8vMOQeLIl1N3Q8=',
   'none', 'dustin', '2026-05-03T21:15:49.098Z'),

  ('tkg-test-ser-1778025587726', 'tk-3-1777839233337', 'test-service-admin',
   'eW7WboiDORrQDBcBI3lbzerwBI7ftnz9qzYUtLx0R1ocm4M6f0mRgmlyf1uP52T2h/kico+tljVw+BIjvFrj4xP0hlYj3iyKrecCazdt+RljNmoWkhOf9UPjB0AZ0yiwVVivlfB3DPbRvITatRGstVpORY1h5Cx+oqIDShv9Y+96hFvYleqK72yDdA8+ZdgLSFee5TtflW6h/prSBCzoPbP7PQx5R7ZVx6UyQX+DRUQd1YdSxm97JcMBhi3yy3IcpsJQr4avqcRBmZV7lw3UwhdUI2lqIesxT4lbhe72bo2zDI6rUv/mnClAe1bCZ04B+Q1B/Uy8Wnf1Cxac5nJSTY3u+EE7zCkEJY4EobB/bcPpw1f4dOMMitYMhVYz4nfwNHanjLpN5xPZQUs/PA97iDvSM5uhoXQVwdJOQ9CRDZzEGYWbNkCxS0M7j0R6uU5Ew4tOIpdOvNFlylNpnd2DqnbVFxUyWvzmJlla4IoFWhoiad8n8Q6bAi+J5jQJ9Hdotr1JNAnRw6zELkn7yQ4TmJu0FNCVpHE4bL4qsvyOVlu44UKCz5pBbUyxZUv+FOGRrnAMoD+C6QgAHPi9f8AsR1tXPg49/lsIRjWWOTCTWkMqxCLvuIveHuYnsgOMKj3qbB7HLclNIrpKSNA/+OBbESL2CYHVzviJhGz3p43V90U=',
   'none', 'test-service-admin', '2026-05-05T23:59:47.726Z');

-- The actual encrypted posts.
-- content column: static placeholder (the server never sees plaintext)
-- ciphertext column: AES-256-GCM encrypted binary blob
-- encryption_iv: random 96-bit IV (base64), unique per post
--
-- YOUR CHALLENGE: recover the original plaintext from these blobs.
INSERT INTO posts (id, tribe_id, author_id, author_name, content, is_encrypted, ciphertext, encryption_iv, ring, created_at) VALUES
  ('57ad33f6-a124-469e-825f-fd3c206b4beb', '3', 'test-service-admin', 'Test Service Admin',
   '🔒 Encrypted post', true,
   E'\\x193b5e80a350cdd1f49cc58de9f68736d4d2ee3bbd54cd3de788b7956b96b41c0c3c15bbb1e5611b05a501402ae56a4943efe7989345575a19367a05157294c1729fd4b8d660bf630ef38f88dc18303bc956bde6d77744bf79f31b1595a921be2d498d472546fba4b9aa4f6423c47fce695753ceafe6a0528e24b3230945e02f3c707b64619b15e98d47d16d',
   'lIDr265Bs61L+cRq', 'tribes', '2026-05-07T04:04:33.441Z'),

  ('19534bf8-8828-442b-8110-36ba8bafb46c', '3', 'test-service-admin', 'Test Service Admin',
   '🔒 Encrypted post', true,
   E'\\x46c453974afd3742a0ed48604fc380dd84e8502c3f23d57beb57a37f43a99426b656db272895ba747e6e7fa0deb283cc358963c61d7152c30399d5c7b2b8a922d3f38836475a4c04e00a92189781ec3c64f698759109df0f248cdf98389b47b25f5a40d1cae14f4ed285b6242e2424eb69724571011832d30e49a3e353c9409639c61572166f9b75c9ac995dca5f',
   'zeY8no8ZFXQk8abC', 'tribes', '2026-05-07T04:04:57.381Z'),

  ('2302acd3-4456-4379-bbf4-29481a242612', '3', 'test-service-member', 'Test Service Member',
   '🔒 Encrypted post', true,
   E'\\x15bf12e2b1d04ef48f7d57934ae70d8170053a9afbe9fd4337711a32766068b9ca78787f6461fc575e13da300eb4a181461778f31bee34a5c83b5becbc430a0821985f1a3606ba1563cb5cb7cd5f73ccc2fa6a1a3483f138b0f87088aa8cce844790e4fedfa901812b9d5693d91e1a30149bf80097449b964b',
   'HbCzVfUQ+O3WvaOe', 'tribes', '2026-05-07T04:06:51.890Z');
