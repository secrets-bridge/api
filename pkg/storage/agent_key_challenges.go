package storage

// Agent enrollment v2 (skills#116): proof-of-possession challenges for
// enrollment and key rotation, and the admin's one-time rotation token.
// Only hashes of nonces and tokens are stored.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// KeyChallenge is one proof-of-possession challenge: a nonce sealed to
// PublicKey, stored as its SHA-256. ParentID is the enrollment token
// (enrollment) or the rotation token (rotation) it is bound to; AgentID
// is set for a rotation challenge only.
type KeyChallenge struct {
	ID                 uuid.UUID
	ParentID           uuid.UUID
	AgentID            uuid.UUID
	PublicKey          []byte
	PublicKeyAlgorithm string
	NonceHash          []byte
	ExpiresAt          time.Time
	UsedAt             *time.Time
	InvalidatedAt      *time.Time
	CreatedAt          time.Time
}

// AgentKeyRotationToken mirrors a row in agent_key_rotation_tokens.
type AgentKeyRotationToken struct {
	ID                        uuid.UUID
	AgentID                   uuid.UUID
	TokenHash                 []byte
	ExpectedPublicKeyVersion  int
	ExpiresAt                 time.Time
	ConsumedAt                *time.Time
	RevokedAt                 *time.Time
	CreatedBy                 string
	CreatedAt                 time.Time
	SupersededOpenRotationIDs []uuid.UUID // set by CreateRotationToken
}

// Sentinels for the challenge and rotation flows. The service maps them
// to generic HTTP errors and keeps the detail for the audit row.
var (
	ErrChallengeNotFound     = errors.New("storage: key challenge not found")
	ErrRotationTokenNotFound = errors.New("storage: key rotation token not found")
	// ErrRotationStale: the agent's key version moved on (or the agent
	// was revoked) after the rotation token was issued.
	ErrRotationStale = errors.New("storage: key rotation is stale")
)

// ChallengeVerifier runs inside the enroll or rotate transaction with
// the challenge row locked. A non-nil error rolls the transaction back
// and is returned unchanged.
type ChallengeVerifier func(ch *KeyChallenge) error

const keyChallengeCols = `id, %s, public_key, public_key_algorithm, nonce_hash,
	expires_at, used_at, invalidated_at, created_at`

func scanKeyChallenge(row pgx.Row, withAgent bool) (*KeyChallenge, error) {
	var c KeyChallenge
	dest := []any{&c.ID, &c.ParentID}
	if withAgent {
		dest = append(dest, &c.AgentID)
	}
	dest = append(dest, &c.PublicKey, &c.PublicKeyAlgorithm, &c.NonceHash,
		&c.ExpiresAt, &c.UsedAt, &c.InvalidatedAt, &c.CreatedAt)
	if err := row.Scan(dest...); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrChallengeNotFound
		}
		return nil, fmt.Errorf("storage: scan key challenge: %w", err)
	}
	return &c, nil
}

// --- enrollment challenges -------------------------------------------

// CreateEnrollmentChallenge inserts a challenge bound to an enrollment
// token. ParentID is the token id.
func (r *AgentEnrollmentTokens) CreateEnrollmentChallenge(ctx context.Context, c *KeyChallenge) error {
	if c.ParentID == uuid.Nil || len(c.PublicKey) == 0 || len(c.NonceHash) == 0 || c.ExpiresAt.IsZero() {
		return errors.New("storage: enrollment challenge is incomplete")
	}
	const q = `
		INSERT INTO agent_enrollment_challenges
			(enrollment_token_id, public_key, public_key_algorithm, nonce_hash, expires_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, created_at`
	if err := r.pool.QueryRow(ctx, q, c.ParentID, c.PublicKey, c.PublicKeyAlgorithm, c.NonceHash, c.ExpiresAt).
		Scan(&c.ID, &c.CreatedAt); err != nil {
		return fmt.Errorf("storage: create enrollment challenge: %w", err)
	}
	return nil
}

// InvalidateEnrollmentChallenge burns an unused challenge, after a
// wrong response, if it belongs to tokenID. Zero rows is not an error.
func (r *AgentEnrollmentTokens) InvalidateEnrollmentChallenge(ctx context.Context, id, tokenID uuid.UUID, at time.Time) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE agent_enrollment_challenges SET invalidated_at = $3
		WHERE id = $1 AND enrollment_token_id = $2 AND used_at IS NULL AND invalidated_at IS NULL`, id, tokenID, at)
	if err != nil {
		return fmt.Errorf("storage: invalidate enrollment challenge: %w", err)
	}
	return nil
}

// EnrollWithChallenge is the enrollment transaction: it burns the token
// (single use, under the row lock, so concurrent enrolls on one token
// serialise and exactly one commits), locks the challenge and hands it
// to verify, creates the agent with the challenge's public key, marks
// the challenge used and links the token to the agent. Any failure
// rolls all of it back. ErrEnrollmentTokenNotFound: the token can no
// longer be consumed. ErrChallengeNotFound: no such challenge.
func (r *AgentEnrollmentTokens) EnrollWithChallenge(ctx context.Context, tokenID, challengeID uuid.UUID, at time.Time, verify ChallengeVerifier, a *Agent) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("storage: begin enrollment: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var consumed uuid.UUID
	err = tx.QueryRow(ctx, `
		UPDATE agent_enrollment_tokens
		SET    consumed_at = $2
		WHERE  id = $1 AND `+consumableTokenSQL+`
		RETURNING id`, tokenID, at).Scan(&consumed)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrEnrollmentTokenNotFound
	}
	if err != nil {
		return fmt.Errorf("storage: consume enrollment token: %w", err)
	}

	ch, err := scanKeyChallenge(tx.QueryRow(ctx,
		`SELECT `+fmt.Sprintf(keyChallengeCols, "enrollment_token_id")+`
		 FROM agent_enrollment_challenges WHERE id = $1 FOR UPDATE`, challengeID), false)
	if err != nil {
		return err
	}
	if err := verify(ch); err != nil {
		return err
	}

	a.PublicKey = ch.PublicKey
	a.PublicKeyAlgorithm = ch.PublicKeyAlgorithm
	if err := insertEnrolledAgent(ctx, tx, a); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE agent_enrollment_challenges SET used_at = $2, used_by_agent_id = $3 WHERE id = $1`,
		challengeID, at, a.ID); err != nil {
		return fmt.Errorf("storage: mark enrollment challenge used: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE agent_enrollment_tokens SET consumed_by_agent_id = $2 WHERE id = $1`,
		tokenID, a.ID); err != nil {
		return fmt.Errorf("storage: link enrollment token to agent: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("storage: commit enrollment: %w", err)
	}
	return nil
}

// --- key rotation ------------------------------------------------------

// AgentKeyRotations is the Postgres repository for rotation tokens and
// rotation challenges.
type AgentKeyRotations struct {
	pool *Pool
}

// NewAgentKeyRotations binds the repository to a pool.
func NewAgentKeyRotations(pool *Pool) *AgentKeyRotations { return &AgentKeyRotations{pool: pool} }

// AgentKeyRotationRepository is the read/write surface the service uses.
type AgentKeyRotationRepository interface {
	CreateToken(ctx context.Context, t *AgentKeyRotationToken, at time.Time) error
	GetTokenByHash(ctx context.Context, hash []byte) (*AgentKeyRotationToken, error)
	CreateChallenge(ctx context.Context, c *KeyChallenge) error
	InvalidateChallenge(ctx context.Context, id, tokenID uuid.UUID, at time.Time) error
	Rotate(ctx context.Context, in RotateKeyInput) (*RotateKeyResult, error)
}

// RotateKeyInput is one rotation confirm.
type RotateKeyInput struct {
	AgentID     uuid.UUID
	TokenID     uuid.UUID
	ChallengeID uuid.UUID
	At          time.Time
	Verify      ChallengeVerifier
}

// RotateKeyResult names the key before and after.
type RotateKeyResult struct {
	OldPublicKey []byte
	NewPublicKey []byte
	OldVersion   int
	NewVersion   int
	// ProviderConnectionID of the agent, for the audit row.
	ProviderConnectionID *uuid.UUID
}

const rotationTokenCols = `id, agent_id, token_hash, expected_public_key_version,
	expires_at, consumed_at, revoked_at, created_by, created_at`

func scanRotationToken(row pgx.Row) (*AgentKeyRotationToken, error) {
	var t AgentKeyRotationToken
	err := row.Scan(&t.ID, &t.AgentID, &t.TokenHash, &t.ExpectedPublicKeyVersion,
		&t.ExpiresAt, &t.ConsumedAt, &t.RevokedAt, &t.CreatedBy, &t.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrRotationTokenNotFound
		}
		return nil, fmt.Errorf("storage: scan rotation token: %w", err)
	}
	return &t, nil
}

// CreateToken issues a rotation token for an agent that is not revoked,
// at the agent's current key version. Any earlier open token for the
// agent is revoked ("superseded") in the same transaction, with its
// open challenges. ErrNotFound: no such agent, or it is revoked.
func (r *AgentKeyRotations) CreateToken(ctx context.Context, t *AgentKeyRotationToken, at time.Time) error {
	if t.AgentID == uuid.Nil || len(t.TokenHash) == 0 || t.CreatedBy == "" || t.ExpiresAt.IsZero() {
		return errors.New("storage: rotation token is incomplete")
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("storage: begin rotation token: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var version int
	err = tx.QueryRow(ctx,
		`SELECT public_key_version FROM agents WHERE id = $1 AND status <> 'revoked' FOR UPDATE`,
		t.AgentID).Scan(&version)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("storage: lock agent for rotation: %w", err)
	}

	rows, err := tx.Query(ctx, `
		UPDATE agent_key_rotation_tokens
		SET    revoked_at = $2, revoke_reason = 'superseded'
		WHERE  agent_id = $1 AND consumed_at IS NULL AND revoked_at IS NULL
		RETURNING id`, t.AgentID, at)
	if err != nil {
		return fmt.Errorf("storage: supersede rotation tokens: %w", err)
	}
	superseded, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return fmt.Errorf("storage: supersede rotation tokens: %w", err)
	}
	if len(superseded) > 0 {
		if _, err := tx.Exec(ctx, `
			UPDATE agent_key_rotation_challenges SET invalidated_at = $2
			WHERE  rotation_token_id = ANY($1) AND used_at IS NULL AND invalidated_at IS NULL`,
			superseded, at); err != nil {
			return fmt.Errorf("storage: invalidate superseded challenges: %w", err)
		}
	}

	t.ExpectedPublicKeyVersion = version
	if err := tx.QueryRow(ctx, `
		INSERT INTO agent_key_rotation_tokens
			(agent_id, token_hash, expected_public_key_version, expires_at, created_by)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, created_at`,
		t.AgentID, t.TokenHash, version, t.ExpiresAt, t.CreatedBy).Scan(&t.ID, &t.CreatedAt); err != nil {
		return fmt.Errorf("storage: create rotation token: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("storage: commit rotation token: %w", err)
	}
	t.SupersededOpenRotationIDs = superseded
	return nil
}

// GetTokenByHash resolves a rotation token by its SHA-256 hash.
func (r *AgentKeyRotations) GetTokenByHash(ctx context.Context, hash []byte) (*AgentKeyRotationToken, error) {
	return scanRotationToken(r.pool.QueryRow(ctx,
		`SELECT `+rotationTokenCols+` FROM agent_key_rotation_tokens WHERE token_hash = $1`, hash))
}

// CreateChallenge inserts a rotation challenge. ParentID is the
// rotation token id, AgentID the agent.
func (r *AgentKeyRotations) CreateChallenge(ctx context.Context, c *KeyChallenge) error {
	if c.ParentID == uuid.Nil || c.AgentID == uuid.Nil || len(c.PublicKey) == 0 || len(c.NonceHash) == 0 || c.ExpiresAt.IsZero() {
		return errors.New("storage: rotation challenge is incomplete")
	}
	const q = `
		INSERT INTO agent_key_rotation_challenges
			(rotation_token_id, agent_id, public_key, public_key_algorithm, nonce_hash, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at`
	if err := r.pool.QueryRow(ctx, q, c.ParentID, c.AgentID, c.PublicKey, c.PublicKeyAlgorithm, c.NonceHash, c.ExpiresAt).
		Scan(&c.ID, &c.CreatedAt); err != nil {
		return fmt.Errorf("storage: create rotation challenge: %w", err)
	}
	return nil
}

// InvalidateChallenge burns an unused rotation challenge of tokenID.
func (r *AgentKeyRotations) InvalidateChallenge(ctx context.Context, id, tokenID uuid.UUID, at time.Time) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE agent_key_rotation_challenges SET invalidated_at = $3
		WHERE id = $1 AND rotation_token_id = $2 AND used_at IS NULL AND invalidated_at IS NULL`, id, tokenID, at)
	if err != nil {
		return fmt.Errorf("storage: invalidate rotation challenge: %w", err)
	}
	return nil
}

// Rotate is the rotation transaction: it burns the rotation token
// (bound to this agent, single use, unexpired), locks the challenge and
// hands it to Verify, then replaces the agent's key and bumps its
// version, but only while the agent is not revoked and still at the
// version the token was issued for. The challenge is marked used and
// the token's other open challenges are invalidated.
func (r *AgentKeyRotations) Rotate(ctx context.Context, in RotateKeyInput) (*RotateKeyResult, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("storage: begin rotation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var expected int
	err = tx.QueryRow(ctx, `
		UPDATE agent_key_rotation_tokens
		SET    consumed_at = $3
		WHERE  id = $1 AND agent_id = $2
		  AND  consumed_at IS NULL AND revoked_at IS NULL AND expires_at > $3
		RETURNING expected_public_key_version`, in.TokenID, in.AgentID, in.At).Scan(&expected)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrRotationTokenNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("storage: consume rotation token: %w", err)
	}

	ch, err := scanKeyChallenge(tx.QueryRow(ctx,
		`SELECT `+fmt.Sprintf(keyChallengeCols, "rotation_token_id, agent_id")+`
		 FROM agent_key_rotation_challenges WHERE id = $1 FOR UPDATE`, in.ChallengeID), true)
	if err != nil {
		return nil, err
	}
	if err := in.Verify(ch); err != nil {
		return nil, err
	}

	res := &RotateKeyResult{NewPublicKey: ch.PublicKey}
	var status AgentStatus
	err = tx.QueryRow(ctx, `
		SELECT status, public_key, public_key_version, provider_connection_id
		FROM agents WHERE id = $1 FOR UPDATE`, in.AgentID).
		Scan(&status, &res.OldPublicKey, &res.OldVersion, &res.ProviderConnectionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrRotationStale
	}
	if err != nil {
		return nil, fmt.Errorf("storage: lock agent for rotation: %w", err)
	}
	if status == AgentStatusRevoked || res.OldVersion != expected {
		return nil, ErrRotationStale
	}

	if err := tx.QueryRow(ctx, `
		UPDATE agents
		SET    public_key = $2,
		       public_key_algorithm = $3,
		       public_key_fingerprint = 'sha256:' || encode(sha256($2::bytea), 'hex'),
		       public_key_version = public_key_version + 1
		WHERE  id = $1
		RETURNING public_key_version`, in.AgentID, ch.PublicKey, ch.PublicKeyAlgorithm).Scan(&res.NewVersion); err != nil {
		return nil, fmt.Errorf("storage: rotate agent key: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE agent_key_rotation_challenges SET used_at = $2 WHERE id = $1`, in.ChallengeID, in.At); err != nil {
		return nil, fmt.Errorf("storage: mark rotation challenge used: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE agent_key_rotation_challenges SET invalidated_at = $3
		WHERE  rotation_token_id = $1 AND id <> $2 AND used_at IS NULL AND invalidated_at IS NULL`,
		in.TokenID, in.ChallengeID, in.At); err != nil {
		return nil, fmt.Errorf("storage: invalidate sibling rotation challenges: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("storage: commit rotation: %w", err)
	}
	return res, nil
}
