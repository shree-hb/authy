require_relative '../../test_helper'

module Authy
class LoginControllerTest < ::ActionController::TestCase
  include Warden::Test::Helpers

  def setup
    request.env["devise.mapping"] = Devise.mappings[:patient]
    dept = create :department
    @provider = create :provider, department: dept
    Rails.application.config.two_factor_authentication = false
  end

  test "that user can login with email" do
    patient = create :patient
    create :patient_provider_relationship, patient: patient, provider: @provider
    post :create, params: { email: patient.email, password: "Secret12345", platform: "android" }
    assert_response :success
    result = JSON.parse(response.body)
    assert_equal patient.id, result["data"]["id"]
    assert result["access_token"]
  end

  test "that user can login with phone" do
    patient = create :patient, email: nil, contact_number: "0987654321", password: "Secret1234"
    create :patient_provider_relationship, patient: patient, provider: @provider
    post :create, params: { contact_number: patient.contact_number, password: "Secret1234", platform: "android", has_accepted_terms_and_condition: true }

    assert_response :success
    result = JSON.parse(response.body)
    assert_equal patient.id, result["data"]["id"]
    assert result["access_token"]
  end

  test "user not active for auth cannot login" do
    skip
    patient = create :patient
    create :patient_provider_relationship, patient: patient, provider: @provider

    Patient.any_instance.stubs(:active_for_authentication?).returns false
    post :create, params: { email: patient.email, password: "Secret1234", platform: "android" }

    assert_response :unauthorized
    result = JSON.parse(response.body)
    assert ["Your account has been locked due to multiple unsuccessful login attempts. Please wait for 30 minutes before trying again."], result["errors"]
  end

  test "should verify the otp for phone number if two factor authentication is enabled" do
    skip
    Rails.application.config.two_factor_authentication = true

    patient = create :patient, email: nil, contact_number: "0987654321", password: "Secret1234"
    patient.user_verifications.create phone_number: "0987654321", code: "123456", sent_time: DateTime.now.utc, attempts: 0
    post :create, params: { contact_number: patient.contact_number, password: "Secret1234", code: "123456", platform: "xzy" }

    assert_response :success
    result = JSON.parse(response.body)
    assert_equal patient.id, result["data"]["id"]
    # assert_equal patient.uid, response.headers["uid"]
    # assert_equal patient.reload.tokens.keys.first, response.headers["client"]
  end

  test "should verify the otp for email if two factor authentication is enabled" do
    skip
    Rails.application.config.two_factor_authentication = true

    patient = create :patient, password: "Secret1234"
    patient.user_verifications.create phone_number: patient.contact_number, code: "123456", sent_time: DateTime.now.utc, attempts: 0
    @request.headers["platform"] = "ABC"
    post :create, params: { email: patient.email, password: "Secret1234", code: "123456" }

    assert_response :success

    result = JSON.parse(response.body)
    assert_equal patient.id, result["data"]["id"]
    # assert_equal patient.uid, response.headers["uid"]
    # assert_equal patient.reload.tokens.keys.first, response.headers["client"]
  end

  test "should return invalid code error if wrong otp and two factor authentication is enabled" do
    skip
    Rails.application.config.two_factor_authentication = true

    patient = create :patient, password: "Secret1234"
    patient.user_verifications.create email: patient.email, code: "123456", sent_time: DateTime.now.utc, attempts: 0
    assert_difference "patient.reload.failed_attempts" do
      post :create, params: { email: patient.email, password: "Secret1234", code: "142345" }

      assert_response :unauthorized
      result = JSON.parse(response.body)
      assert_equal "Incorrect one time password.", result["errors"].first
      assert_not result["success"]
    end
  end

  test "should return invalid code error and lock user account if wrong otp and failed attempts exceeded and two factor authentication is enabled" do
    Rails.application.config.two_factor_authentication = true

    patient = create :patient, password: "Secret1234", failed_attempts: 10
    patient.user_verifications.create email: patient.email, code: "123456", sent_time: DateTime.now.utc, attempts: 0
    assert_not patient.access_locked?

    post :create, params: { email: patient.email, password: "Secret1234", code: "142345" }

    assert_response :unauthorized
    result = JSON.parse(response.body)
    assert_equal "Incorrect one time password.", result["errors"].first
    assert_not result["success"]
    assert patient.reload.access_locked?
  end

  test "that users provider should change to contact_number when logged in using contact_number" do
    patient = create :patient, email: "test121@higgsbosonhealth.com", contact_number: "0987654321", password: "Secret1234", provider: "email", uid: "test121@higgsbosonhealth.com"
    create :patient_provider_relationship, patient: patient, provider: @provider

    post :create, params: { contact_number: patient.contact_number, password: "Secret1234", platform: "android" }

    assert_response :success
    patient.reload
    assert_equal "contact_number", patient.provider
  end

  test "that users provider should change to email when logged in using email" do
    patient = create :patient, email: "test121@higgsbosonhealth.com", contact_number: "0987654321", password: "Secret1234", provider: "contact_number", uid: "0987654321"
    create :patient_provider_relationship, patient: patient, provider: @provider

    post :create, params: { email: patient.email, password: "Secret1234", platform: "android" }

    assert_response :success
    patient.reload
    assert_equal "email", patient.provider
  end

  test "user should not be able to login with wrong credentials" do
    patient = create :patient
    create :patient_provider_relationship, patient: patient, provider: @provider
    post :create, params: { email: patient.email, password: "WrongPassword124" }

    assert_response :unauthorized
    result = JSON.parse(response.body)
    assert_equal "Check password for spelling errors or try to sign in with your mobile number instead.", result["errors"].first
  end

  test "that user can login with supported version of app for ios" do
    patient = create :patient
    create :patient_provider_relationship, patient: patient, provider: @provider
    post :create, params: { email: patient.email, password: "Secret12345", app_version: "1.0.1", platform: "ios" }

    assert_response :success
    result = JSON.parse(response.body)
    assert_equal patient.id, result["data"]["id"]
    assert result["access_token"]
  end

  test "that user can login with supported version of app for android" do
    patient = create :patient
    create :patient_provider_relationship, patient: patient, provider: @provider
    post :create, params: { email: patient.email, password: "Secret12345", app_version: "3", platform: "android" }

    assert_response :success
    result = JSON.parse(response.body)
    assert_equal patient.id, result["data"]["id"]
    assert result["access_token"]
  end

  test "user should not be able to login with unsupported version of app for ios" do
    patient = create :patient
    create :patient_provider_relationship, patient: patient, provider: @provider
    post :create, params: { email: patient.email, password: "Secret1234", app_version: "0.0.0", platform: "ios" }

    assert_response :ok
    result = JSON.parse(response.body)
    assert_equal "Please update to the latest version of the app.", result["error"]
    assert_equal "true", response.headers["X-is-app-upgrade-required"]
  end

  test "user should not be able to login with unsupported version of app for android" do
    patient = create :patient
    create :patient_provider_relationship, patient: patient, provider: @provider
    post :create, params: { email: patient.email, password: "Secret1234", app_version: "0", platform: "android" }

    assert_response :ok
    result = JSON.parse(response.body)
    assert_equal "Please update to the latest version of the app.", result["error"]
    assert_equal "true", response.headers["X-is-app-upgrade-required"]
  end

  test "unconfirmed user should not be able to login" do
    patient = create :patient, confirmed_at: nil
    create :patient_provider_relationship, patient: patient, provider: @provider
    post :create, params: { email: patient.email, password: "Secret12345" }, as: :json

    assert_response :unauthorized
    result = JSON.parse(response.body)
    assert_equal "You have to confirm your email address before continuing.", result["errors"].first
    assert_not result["success"]
  end

  test "deleted user should not be able to login" do
    patient = create :patient, account_deletion_requested_at: DateTime.current
    create :patient_provider_relationship, patient: patient, provider: @provider
    post :create, params: { email: patient.email, password: "Secret1234" }, as: :json

    assert_response :unauthorized
    result = JSON.parse(response.body)
    assert_equal "User account does not exist.", result["errors"].first
    assert_not result["success"]
  end

  test "locked user should not be able to login" do
    patient = create :patient, locked_at: DateTime.current
    create :patient_provider_relationship, patient: patient, provider: @provider
    post :create, params: { email: patient.email, password: "Secret1234" }

    assert_response :unauthorized
    result = JSON.parse(response.body)
    assert_equal "Your account is locked for exceeding maximum attempts. Please try again in 15 minutes.", result["errors"].first
    assert_not result["success"]
  end

  test "locked user should be able to login after 30 minutes" do
    patient = create :patient, locked_at: DateTime.current - 1.hour
    create :patient_provider_relationship, patient: patient, provider: @provider
    post :create, params: { email: patient.email, password: "Secret12345", platform: "android" }

    assert_response :success
    result = JSON.parse(response.body)
    assert_equal patient.id, result["data"]["id"]
    assert result["access_token"]
  end

  test "should create a login request for failed creds email" do
    assert_difference -> { LoginRequest.count } do
      post :create, params: { email: 'sample_email@example.com', password: "Secret12345", platform: "android" }
    end

    assert_response :unauthorized
    result = JSON.parse(response.body)
    assert ["Check password for spelling errors or try to sign in with your mobile number instead."], result["errors"]
  end

  test "should create a login request for failed creds phone" do
    assert_difference -> { LoginRequest.count } do
      post :create, params: { contact_number: '0123456789', password: "Secret1234", platform: "android" }
    end

    assert_response :unauthorized
    result = JSON.parse(response.body)
    assert ["Check password for spelling errors or try to sign in with your email instead."], result["errors"]
  end

  test "that after caregiver logs out patient tokens are removed" do
    department = create :department
    procedure = create :procedure, :with_consent_form, department: department
    provider = create :provider, :push_notification_preference, department: department
    patient = create :patient, :push_notification_preference
    create :patient_provider_relationship, patient: patient, provider: provider
    create :user_procedure, user: patient, performed_by: provider, procedure: procedure
    caregiver = create :caregiver
    create :care_taker_membership, patient: patient, caregiver: caregiver

    patient_token_1 = patient.generate_jwt
    patient_token_2 = patient.generate_jwt
    set_auth_headers(caregiver)
    @request.headers["platform"] = "ABC"
    MasqueradeSession.create(session_uuid: patient_token_1, caregiver_id: caregiver.id, user_id: patient.id)

    assert_difference "JwtBlacklist.count", 1 do
      delete :destroy
    end
  end

  test "provider should not be logged in if their account is deactivated" do
    skip
    dept = create :department
    provider = create :provider, department: dept, is_active: false
    super_user = create :provider, has_super_user_privileges: true, is_admin: true, department: dept

    set_auth_headers(super_user)

    post :create, params: { email: provider.email, password: "Secret1234"}
    assert_response :unauthorized
    result = JSON.parse(response.body)
    assert_equal "Your account has been locked due to multiple unsuccessful login attempts. Please wait for 30 minutes before trying again.", result["errors"][0]
  end
end
end
