//! The three short-lived flow states that used to live in `AppState` — §6.1.
//!
//! They are rows now, so a restart or a second instance sees the same interaction, pending TOTP
//! enrollment and WebAuthn challenge. The update methods filter on `consumed` and expiry and return
//! the new row; when no row comes back the caller reads it once to classify the failure
//! (`not_found`, `expired`, `consumed`, `not_signed_in`). Every one-shot transition is therefore a
//! single conditional `UPDATE`, not a read-then-write race.

use serde_json::Value;
use sqlx::FromRow;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{Store, StoreError, TenantRow, q};

const INTERACTION_COLUMNS: &str = "payload, consumed, signed_in_account, session_id, mfa_account, \
                                   mfa_enrollment, mfa_satisfied, mfa_attempts, expires_at";

/// One `tenant.interactions` row.
#[derive(Debug, Clone, FromRow)]
pub struct InteractionRow {
    /// The authorize request, as JSON.
    pub payload: Value,
    /// Set once the flow is redeemed.
    pub consumed: bool,
    /// The account that signed in, before consent.
    pub signed_in_account: Option<Uuid>,
    /// The SSO session established by that sign-in.
    pub session_id: Option<Uuid>,
    /// The account that passed the primary factor and owes a second factor.
    pub mfa_account: Option<Uuid>,
    /// The account parked on a mandatory enrollment step.
    pub mfa_enrollment: Option<Uuid>,
    /// Whether a completed enrollment already satisfied this interaction.
    pub mfa_satisfied: bool,
    /// Wrong second-factor codes tried on this interaction.
    pub mfa_attempts: i32,
    /// When the row stops being usable.
    pub expires_at: OffsetDateTime,
}

impl Store {
    /// Insert a new interaction, sweeping rows that already expired.
    pub async fn interaction_put(
        &self,
        tenant: &TenantRow,
        id: &str,
        payload: &Value,
        expires_at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        sqlx::query("DELETE FROM tenant.interactions WHERE expires_at <= now()")
            .execute(&pool)
            .await?;
        sqlx::query(
            "INSERT INTO tenant.interactions (id, payload, expires_at) VALUES ($1,$2,$3)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(id)
        .bind(payload)
        .bind(expires_at)
        .execute(&pool)
        .await?;
        Ok(())
    }

    /// Read an interaction without consuming it.
    pub async fn interaction_get(
        &self,
        tenant: &TenantRow,
        id: &str,
    ) -> Result<Option<InteractionRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, InteractionRow>(q(format!(
            "SELECT {INTERACTION_COLUMNS} FROM tenant.interactions WHERE id = $1"
        )))
        .bind(id)
        .fetch_optional(&pool)
        .await?)
    }

    /// Mark an interaction consumed. Only the first caller receives the row.
    pub async fn interaction_consume(
        &self,
        tenant: &TenantRow,
        id: &str,
    ) -> Result<Option<InteractionRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, InteractionRow>(q(format!(
            "UPDATE tenant.interactions SET consumed = true
             WHERE id = $1 AND consumed = false AND expires_at > now()
             RETURNING {INTERACTION_COLUMNS}"
        )))
        .bind(id)
        .fetch_optional(&pool)
        .await?)
    }

    /// Record that `account` authenticated, leaving the interaction for consent.
    pub async fn interaction_mark_signed_in(
        &self,
        tenant: &TenantRow,
        id: &str,
        account: Uuid,
        session_id: Uuid,
    ) -> Result<Option<InteractionRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, InteractionRow>(q(format!(
            "UPDATE tenant.interactions
             SET signed_in_account = $2, session_id = $3
             WHERE id = $1 AND consumed = false AND expires_at > now()
             RETURNING {INTERACTION_COLUMNS}"
        )))
        .bind(id)
        .bind(account)
        .bind(session_id)
        .fetch_optional(&pool)
        .await?)
    }

    /// Consume a signed-in interaction, returning it with the account and session.
    pub async fn interaction_take_signed_in(
        &self,
        tenant: &TenantRow,
        id: &str,
    ) -> Result<Option<InteractionRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, InteractionRow>(q(format!(
            "UPDATE tenant.interactions SET consumed = true
             WHERE id = $1 AND consumed = false AND expires_at > now()
               AND signed_in_account IS NOT NULL
             RETURNING {INTERACTION_COLUMNS}"
        )))
        .bind(id)
        .fetch_optional(&pool)
        .await?)
    }

    /// Park the interaction on a TOTP challenge, resetting the attempt counter for a new account.
    pub async fn interaction_mfa_pending(
        &self,
        tenant: &TenantRow,
        id: &str,
        account: Uuid,
    ) -> Result<Option<InteractionRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, InteractionRow>(q(format!(
            "UPDATE tenant.interactions
             SET mfa_attempts = CASE WHEN mfa_account IS DISTINCT FROM $2 THEN 0 ELSE mfa_attempts END,
                 mfa_account = $2, mfa_enrollment = NULL
             WHERE id = $1 AND consumed = false AND expires_at > now()
             RETURNING {INTERACTION_COLUMNS}"
        )))
        .bind(id)
        .bind(account)
        .fetch_optional(&pool)
        .await?)
    }

    /// Park the interaction on a mandatory enrollment step.
    pub async fn interaction_mfa_enrollment(
        &self,
        tenant: &TenantRow,
        id: &str,
        account: Uuid,
    ) -> Result<Option<InteractionRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, InteractionRow>(q(format!(
            "UPDATE tenant.interactions
             SET mfa_account = NULL, mfa_enrollment = $2, mfa_satisfied = false
             WHERE id = $1 AND consumed = false AND expires_at > now()
             RETURNING {INTERACTION_COLUMNS}"
        )))
        .bind(id)
        .bind(account)
        .fetch_optional(&pool)
        .await?)
    }

    /// Drop the second-factor challenge after a code verified.
    pub async fn interaction_clear_mfa_pending(
        &self,
        tenant: &TenantRow,
        id: &str,
    ) -> Result<Option<InteractionRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, InteractionRow>(q(format!(
            "UPDATE tenant.interactions
             SET mfa_account = NULL, mfa_attempts = 0
             WHERE id = $1 AND consumed = false AND expires_at > now()
             RETURNING {INTERACTION_COLUMNS}"
        )))
        .bind(id)
        .fetch_optional(&pool)
        .await?)
    }

    /// Mark a completed enrollment as satisfying this interaction.
    pub async fn interaction_mfa_satisfied(
        &self,
        tenant: &TenantRow,
        id: &str,
    ) -> Result<Option<InteractionRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, InteractionRow>(q(format!(
            "UPDATE tenant.interactions
             SET mfa_account = NULL, mfa_enrollment = NULL, mfa_attempts = 0, mfa_satisfied = true
             WHERE id = $1 AND consumed = false AND expires_at > now()
             RETURNING {INTERACTION_COLUMNS}"
        )))
        .bind(id)
        .fetch_optional(&pool)
        .await?)
    }

    /// Count one rejected second-factor attempt atomically.
    pub async fn interaction_record_mfa_failure(
        &self,
        tenant: &TenantRow,
        id: &str,
    ) -> Result<Option<i32>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let row: Option<(i32,)> = sqlx::query_as(
            "UPDATE tenant.interactions SET mfa_attempts = mfa_attempts + 1
             WHERE id = $1 AND consumed = false AND expires_at > now()
             RETURNING mfa_attempts",
        )
        .bind(id)
        .fetch_optional(&pool)
        .await?;
        Ok(row.map(|(attempts,)| attempts))
    }

    /// Store a sealed TOTP enrollment, replacing an abandoned one for the same account.
    pub async fn totp_enrollment_put(
        &self,
        tenant: &TenantRow,
        account: Uuid,
        secret_enc: &[u8],
        expires_at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        sqlx::query("DELETE FROM tenant.totp_enrollments WHERE expires_at <= now()")
            .execute(&pool)
            .await?;
        sqlx::query(
            "INSERT INTO tenant.totp_enrollments (account_id, secret_enc, expires_at)
             VALUES ($1,$2,$3)
             ON CONFLICT (account_id) DO UPDATE
             SET secret_enc = EXCLUDED.secret_enc, expires_at = EXCLUDED.expires_at",
        )
        .bind(account)
        .bind(secret_enc)
        .bind(expires_at)
        .execute(&pool)
        .await?;
        Ok(())
    }

    /// The sealed secret of a pending enrollment that has not expired.
    pub async fn totp_enrollment_get(
        &self,
        tenant: &TenantRow,
        account: Uuid,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let row: Option<(Vec<u8>,)> = sqlx::query_as(
            "SELECT secret_enc FROM tenant.totp_enrollments
             WHERE account_id = $1 AND expires_at > now()",
        )
        .bind(account)
        .fetch_optional(&pool)
        .await?;
        Ok(row.map(|(secret,)| secret))
    }

    /// Forget a pending enrollment.
    pub async fn totp_enrollment_delete(
        &self,
        tenant: &TenantRow,
        account: Uuid,
    ) -> Result<(), StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        sqlx::query("DELETE FROM tenant.totp_enrollments WHERE account_id = $1")
            .bind(account)
            .execute(&pool)
            .await?;
        Ok(())
    }

    /// Store a WebAuthn challenge, sweeping expired ones first.
    pub async fn passkey_challenge_put(
        &self,
        tenant: &TenantRow,
        key: &str,
        challenge: &[u8],
        expires_at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        sqlx::query("DELETE FROM tenant.passkey_challenges WHERE expires_at <= now()")
            .execute(&pool)
            .await?;
        sqlx::query(
            "INSERT INTO tenant.passkey_challenges (key, challenge, expires_at) VALUES ($1,$2,$3)
             ON CONFLICT (key) DO UPDATE
             SET challenge = EXCLUDED.challenge, expires_at = EXCLUDED.expires_at",
        )
        .bind(key)
        .bind(challenge)
        .bind(expires_at)
        .execute(&pool)
        .await?;
        Ok(())
    }

    /// Take a challenge; the row is deleted whether or not it is valid, so every ceremony is one-shot.
    pub async fn passkey_challenge_take(
        &self,
        tenant: &TenantRow,
        key: &str,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let row: Option<(Vec<u8>,)> = sqlx::query_as(
            "DELETE FROM tenant.passkey_challenges
             WHERE key = $1 AND expires_at > now()
             RETURNING challenge",
        )
        .bind(key)
        .fetch_optional(&pool)
        .await?;
        Ok(row.map(|(challenge,)| challenge))
    }
}
