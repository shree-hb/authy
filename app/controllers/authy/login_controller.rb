# Extending the Devise Sessions controller with custom methods.
# The codebase below has been moved from 'overrides/sessions' controller 
module Authy
  class LoginController < ::Devise::SessionsController #{}ActionController::Base # #{}::ApplicationController
    include ::WebRequestConcern
    include ::UnsupportedAppVersionConcern
    include ::LoginEventConcern
    include ::UserVerificationConcern

    skip_before_action :verify_signed_out_user, only: :destroy
    before_action :ensure_minimum_app_version, :set_user, only: :create
        
    def create
      puts '***************** CREATE ::  from Login engine ************************'
      handle_failed_login unless @user.present?
  
      # Handle Real user
  
      check_create_constraints; return if performed?
  
      if !(!@user.respond_to?(:active_for_authentication?) || @user.active_for_authentication?)
        @resource = @user
        return render_error_for_disabled unless @user.is_active
        render_create_error_not_confirmed
  
        return
      end
  
      create_session_for_real_user; return if performed?
      puts '***************** CREATE ::  from Login engine ************************'

      render_error_for_incorrect_contact
    end
  
    def destroy
      puts '***************** DESTROY  ::  from Login engine ************************'

      jwt_token = if cookies[:secure_token]
                    cookies[:secure_token].split(" ")[1]
                  else
                    request.headers["Authorization"]&.split(" ")[1]
                  end
      JwtWrapper.blacklist(jwt_token)

      refresh_token = cookies[:refresh_token]
      JwtWrapper.blacklist_refresh_token(refresh_token)
      cookies.delete(:refresh_token)
      cookies.delete(:secure_token)

      # current_user.notification_preference = 'SmsNotification' if current_user.logged_in_mobile_devices.blank?
      UserActivity.find_by(token: refresh_token).try(:destroy)
      if current_user.is_a?(Caregiver)
        platform = params[:platform] || request.headers[:platform]
        is_mobile_request = platform.downcase == "ios" || platform.downcase == "android"
        sessions = MasqueradeSession.where(caregiver_id: current_user.id)
        sessions.each do |session|
          patient = session.try(:user)
          if patient.present?
            JwtWrapper.blacklist_refresh_token(jti: session.session_uuid)
          end
        end
      end
      if current_user.present?
        AnalyticsService.track(current_user.segment_id, AnalyticsService::EVENTS[:signed_out], {platform: params[:platform] || request.headers[:platform]})
      end
      puts '***************** DESTROY  ::  from Login engine ************************'
      if params[:sign_out_path].present?
        redirect_to params[:sign_out_path]
      else
        super
      end
    end
  
    def render_create_success
      if params[:has_accepted_terms_and_condition].present?
        if params[:has_accepted_terms_and_condition] || params[:has_accepted_terms_and_condition].downcase == "true"
          TermsAndConditionAcceptance.create(user: @resource)
        end
      end
      handle_web_signin
      # handle_login_event(@resource.id) - This is moved to procedure specific events/index route (based on first_access_at)
      if params[:contact_number].present? && @resource.provider == "email"
        @resource.uid = @resource.contact_number
        @resource.provider = "contact_number"
      elsif params[:email].present? && @resource.provider == "contact_number"
        @resource.uid = @resource.email
        @resource.provider = "email"
      end
      @resource.save

      if cookies[:secure_token].present?
        redirect_to "/crudify/cruds"
      else
        render "user/login_info"
      end
    end
  
    def find_resource(field, value)
      q = "#{field.to_s} = ?"
      if ActiveRecord::Base.connection.adapter_name.downcase.starts_with? "mysql"
        q = q
      end
      if field.to_s == 'email'
        @resource = resource_class.where(email: value).first
      elsif field.to_s == 'contact_number'
        @resource = resource_class.where(contact_number: value).first
      end
    end
  
    def render_create_error_not_confirmed
      if @resource.confirmed_at.present? || @resource.contact_number.present?
        render_create_error_confirmed
        return
      end
  
      render json: {
        success: false,
        errors: [I18n.t("devise.failure.unconfirmed", email: @resource.email)]
      }, status: 401
    end
  
    def handle_failed_login
      login_request = get_login_request()
  
      if login_request && login_request.access_locked?
        return render json: { errors: [I18n.t("devise_token_auth.sessions.not_confirmed")] }, status: 401
      end
  
      update_login_request(login_request)
  
      if params[:email].present?
        LoginRequest.create(email: params[:email], failed_attempts: 1) unless login_request
        render json: { errors: ["Check password for spelling errors or try to sign in with your mobile number instead."] }, status: 401
      else
        LoginRequest.create(contact_number: params[:contact_number], failed_attempts: 1) unless login_request
        render json: { errors: ["Check password for spelling errors or try to sign in with your email instead."] }, status: 401
      end
    end
  
    def ensure_minimum_app_version
      return unless is_request_from_unsupported_version?
  
      return render json: { message: "This app version is no longer supported",
                            error: "Please update to the latest version of the app." }, status: :ok
    end
  
    private
  
    def render_create_error_confirmed
      if @resource.account_deletion_requested_at.present?
        render json: {
          success: false,
          errors: [I18n.t("devise_token_auth.sessions.deletion_requested", email: @resource.email)]
        }, status: 401
      else
        render json: {
          success: false,
          errors: [I18n.t("devise_token_auth.sessions.locked", email: @resource.email)]
        }, status: 401
      end
    end
  
    def create_session_for_real_user
      return unless @user && @user.valid_for_authentication? { @user.valid_password?(params[:password]) }
      platform = params[:platform] || request.headers[:platform]
      if @user && (@user.type == "Patient" || @user.type == "Caregiver") && platform && platform.downcase == "web" && !params[:is_existing_user]
        return render json: {errors: [I18n.t('devise_token_auth.sessions.invalid_user_type_platform_login')]}, status: 400
      end
      if Rails.application.config.two_factor_authentication
        is_successful, return_code = UserVerificationService.verify_otp(@user, params[:code], phone_number: @user.contact_number)
        if return_code == "verification_attempts_exceeded"
          lock_user_access(@user)
          return render json: { errors: ["Your account is locked for exceeding maximum attempts. Please try again in 15 minutes."] }, status: 401
        elsif return_code == "invalid_code"
          lock_user_access(@user)
          return render json: { errors: ["Incorrect one time password."] }, status: 401
        end
      end
      sign_in(@user.class.name.downcase, @user)
      @user.failed_attempt_count = 0
      @user.last_attempt_failed_at = nil
      @user.save!
      @resource = @user
      platform = params[:platform] || request.headers[:platform]
      is_mobile_request = platform.downcase == "ios" || platform.downcase == "android"
      @token = JwtWrapper.encode(
        {sub: @user.id, iat: @user.invalidate_tokens_before&.to_i},
        is_mobile_request: is_mobile_request
      )
      refresh_token = JwtWrapper.create_refresh_token(@user, is_mobile_request: is_mobile_request)
      cookies.delete(:refresh_token)
      cookies[:refresh_token] = {
        value: refresh_token,
        httponly: true,
        secure: true
      }

      is_from_internal = params[:is_from_crudify] == "1"
      cookies[:secure_token] = 'Bearer ' + @token if is_from_internal
      
      traits = {
        platform: platform,
        type: @user.is_a?(Provider) ? 'Provider' : @user.is_a?(PatientAdvocate) ? 'Advisor' : @user.type
      }
      if @user.HealthcareProvider?
        traits[:user_type] = @user.user_type
        traits[:is_super_user] = @user.has_super_user_privileges
      end
      
      AnalyticsService.track(@user.segment_id, AnalyticsService::EVENTS[:signed_in], traits )
      render_create_success
    end
  
    def check_create_constraints
      if @user && !@user.confirmed?
        render json: { errors: [I18n.t("devise.failure.unconfirmed")] }, status: 401
      elsif @user && @user.confirmed_at.nil? && @user.contact_number.nil?
        render json: { errors: ["You have to confirm your account before continuing."] }, status: 401
      elsif @user && @user.account_deletion_requested_at.present?
        render json: { errors: ["User account does not exist."] }, status: 401
      elsif @user && @user.access_locked?
        render json: { errors: [I18n.t("devise_token_auth.sessions.not_confirmed")] }, status: 401
      end
    end
  
    def render_error_for_incorrect_contact
      if params[:email].present?
        render json: { errors: ["Check password for spelling errors or try to sign in with your mobile number instead."] }, status: 401
      else
        render json: { errors: ["Check password for spelling errors or try to sign in with your email instead."] }, status: 401
      end
    end

    def render_error_for_disabled
      render json: {
        success: false,
        errors: [I18n.t("devise_token_auth.sessions.disabled", email: @resource.email)]
      }, status: 401
    end
  end  
end
