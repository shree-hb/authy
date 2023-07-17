class JwtWrapper
  def self.encode(payload, is_mobile_request: false)
    expiration = is_mobile_request ? Rails.application.secrets.mobile_jwt_expiration_minutes : Rails.application.secrets.jwt_expiration_minutes

    payload = payload.dup
    payload['exp'] = expiration.to_i.minutes.from_now.to_i
    payload['jti'] = payload['jti'] || SecureRandom.uuid
    JWT.encode payload, Rails.application.secrets.secret_key_base, 'HS256'
  end

  def self.decode(token)
    begin
      decoded_token = JWT.decode token, Rails.application.secrets.secret_key_base, true, { algorithm: 'HS256' }
      decoded_token.first
    rescue
      nil
    end
  end

  def self.blacklist(token)
    payload = decode(token)
    if payload
      JwtBlacklist.find_or_create_by(jti: payload['jti'], expires_at: Time.at(payload['exp']))
    end
  end

  def self.blacklist_jti(jti, created_at, is_mobile_request: false)
    expiration = is_mobile_request ? Rails.application.secrets.mobile_jwt_expiration_minutes : Rails.application.secrets.jwt_expiration_minutes
    expires_at = created_at + expiration.to_i.minutes
    JwtBlacklist.find_or_create_by(jti: jti, expires_at: expires_at)
  end

  def self.create_refresh_token(user, jti: SecureRandom.uuid, is_mobile_request: false)
    expiration = expiration = is_mobile_request ? Rails.application.secrets.mobile_refresh_token_expiration_hours : Rails.application.secrets.refresh_token_expiration_hours

    expires_at = expiration.to_i.hours.from_now
    payload = { sub: user.id, exp: expires_at.to_i, jti: jti, iat: user.invalidate_tokens_before&.to_i }

    $redis.set(jti, user.id, ex: expiration.to_i.hours)
    JWT.encode payload, Rails.application.secrets.secret_key_base, 'HS256'
  end

  def self.blacklist_refresh_token(token = nil, jti: nil)
    if jti
      $redis.del(jti)
    else
      payload = decode(token)
      $redis.del(payload['jti']) if payload
    end
  end
end
