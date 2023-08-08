# authy_gem/test/test_helper.rb
ENV['RAILS_ENV'] ||= 'test'
# require File.expand_path('/Users/chintamanipatil/ins-server/test/test_helper.rb', __dir__)
require File.expand_path(`#{::Rails.root}/test/test_helper.rb`, __dir__)

FactoryGirl.definition_file_paths << File.expand_path(`#{::Rails.root}/test/factories`, __FILE__)
FactoryGirl.find_definitions
FactoryGirl.reload

class ActiveSupport::TestCase
  include ::FactoryGirl::Syntax::Methods
end
