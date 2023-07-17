module Devise
  module Strategies
    class Token < Base

      def valid?
        cookies[:secure_token].present?
      end

      def store?
        false
      end
      
      def authenticate!
        return generate_new_token if no_claims

        return if no_claims || no_claimed_sub

        return if is_blacklisted?

        user = mapping.to.find_by_id claims['sub']
        return unless user

        if (user.invalidate_tokens_before&.to_i <= claims['iat']&.to_i)
          env['devise.skip_trackable'.freeze] = true
          success! user
        else
          JwtBlacklist.find_or_create_by(jti: claims['jti'], expires_at: Time.at(claims['exp']))
        end
      end

      private

      def bearer_header
        cookies[:secure_token]&.to_s
      end

      def is_blacklisted?
        JwtBlacklist.where(jti: claims['jti']).exists?
      end

      def no_claims
        !claims
      end

      def no_claimed_sub
        !claims.has_key?('sub')
      end

      def token
        return nil if bearer_header.nil?
        strategy, jwt_token = bearer_header.split(' ')
        return nil if (strategy || '').downcase != 'bearer'
        jwt_token
      end

      def claims
        JwtWrapper.decode(token) rescue nil
      end

      def is_masquerade_session?
        cookies[:masquerade_refresh_token].present?
      end

      def generate_new_token
        user = get_refresh_token_user

        if user && (is_mobile_request? || recent_user_activity?(user))
          if is_masquerade_session?
            uuid = SecureRandom.uuid
            Rails.cache.write("new_masquerade_token_for_#{user.id}",user.generate_jwt({ "jti" => uuid }, is_mobile_request: is_mobile_request?))
          else
            Rails.cache.write("new_token_for_#{user.id}",user.generate_jwt(is_mobile_request: is_mobile_request?))
          end
          env['devise.skip_trackable'.freeze] = true
          success! user
        end
      end

      def get_refresh_token_user
        refresh_token_cookie = is_masquerade_session? ? cookies[:masquerade_refresh_token] : cookies[:refresh_token]
        return invalid_refresh_token if refresh_token_cookie.blank?

        decoded_token = JwtWrapper.decode(refresh_token_cookie)
        return invalid_refresh_token if decoded_token.blank? || decoded_token['sub'].nil?

        user = mapping.to.find_by_id decoded_token['sub']
        return unless user

        return invalid_refresh_token(decoded_token['jti']) if user.invalidate_tokens_before&.to_i > decoded_token['iat']&.to_i

        refresh_token = $redis.get(decoded_token['jti'])
        return invalid_refresh_token if refresh_token.blank?

        user
      end

      def invalid_refresh_token(refresh_token = nil)
        cookies.delete(:refresh_token)
        cookies.delete(:masquerade_refresh_token)
        $redis.del(refresh_token) if refresh_token
        return nil
      end

      def is_valid_refresh_token_request?
        !["/notifications/unread_count"].include?(request.path)
      end

      def is_mobile_request?
        platform = params[:platform] || request.headers[:platform]
        platform.try(:downcase) == "ios" || platform.try(:downcase) == "android"
      end

      def recent_user_activity?(user)

        expiry_time = Settings.web_request.token_expiry_time_in_minutes
        refresh_token_cookie = is_masquerade_session? ? cookies[:masquerade_refresh_token] : cookies[:refresh_token]

        latest_user_activity = user.user_activities.where(platform: UserActivity.platforms[:web], token: refresh_token_cookie).order(:updated_at).last

        if latest_user_activity && latest_user_activity.updated_at >= (DateTime.now.utc - expiry_time.minutes)
          return true
        end
        false
      end
    end
  end
end
